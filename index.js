const {get, isEmpty} = require('lodash');
const {sleep, dedup, limit} = require('@raychee/utils');


class Dummy {
    constructor(proxy) {
        this.proxy = proxy;
    }

    async get() {
        return this.proxy;
    }

    async touch() {
    }

    async deprecate() {
    }

    async remove() {
    }
    
    async _unload() {
    }
    
    async _destroy() {
    }
}


module.exports = {

    type: 'proxies',

    factory({proxyTypes = {}} = {}) {

        class Proxies {

            constructor(logger, name, pluginLoader, {stored = false} = {}) {
                this.logger = logger;
                this.name = name;

                this._proxies = {};
                this._stored = stored;
                this._pluginLoader = pluginLoader;
                this._request = undefined;
                this._nextTimeRequestProxyList = 0;

                this._load = limit(Proxies.prototype._load.bind(this), 1);
                this._requestProxyList = dedup(Proxies.prototype._requestProxyList.bind(this), {key: null});
                this._syncStoreForce = dedup(Proxies.prototype._syncStoreForce.bind(this), {queue: 1});
            }

            async _init(store) {
                if (this._stored) {
                    store = get(await this.logger.pull(), this.name);
                    if (!store) {
                        this.logger.crash(
                            'proxies_invalid_name', 'invalid proxies name: ', this.name, ', please make sure: ',
                            '1. there is a document in the internal collection service.Store that matches filter {plugin: \'proxies\'}, ',
                            '2. there is a valid entry under document field \'data.', this.name, '\''
                        );
                    }
                }
                await this._load(store);
            }

            async _load({type, options, proxies = {}} = {}) {
                const {minIntervalBetweenStoreUpdate} = this._options || {};
                // const {
                //     url, 
                //     maxDeprecationsBeforeRemoval = 1, minIntervalBetweenUse = 0, recentlyUsedFirst = true,
                //     minIntervalBetweenRequest = 5, minIntervalBetweenStoreUpdate = 10,
                //     proxiesWithIdentityTTL = 24 * 60 * 60, maxRetryRequest = -1, 
                // } = options;
                this._options = this._makeOptions(options);
                if (minIntervalBetweenStoreUpdate !== this._options.minIntervalBetweenStoreUpdate) {
                    this._syncStoreForce = dedup(
                        Proxies.prototype._syncStoreForce.bind(this),
                        {within: this._options.minIntervalBetweenStoreUpdate * 1000, queue: 1}
                    );
                }
                this._request = await this._pluginLoader.get({type: 'request', ...options._request});
                if (type) this.type = type;
                if (!proxyTypes[this.type]) {
                    this.logger.crash('proxies_bad_config', this._logPrefix(), 'unknown proxies type: ', this.type);
                }
                for (const proxy of this._iterProxies(proxies)) {
                    const id = this._id(proxy);
                    this._proxies[id] = {...proxy, ...this._proxies[id]};
                }
            }

            async _requestProxyList(logger) {
                logger = logger || this.logger;
                let trial = 0, ignoreRequestInterval = false;
                while (true) {
                    trial++;
                    if (!this._options.url) {
                        if (this._options.allowNoProxy) {
                            this._warn(logger, 'proxies url is not specified, so no proxy can be loaded.');
                            return false;
                        } else {
                            if (this._stored) {
                                while (!this._options.url) {
                                    const store = await this.logger.pull({
                                        waitUntil: s => get(s, [this.name, 'options', 'url']),
                                        message: `${this.name}.options.url need to be valid`
                                    }, logger);
                                    await this._load(store);
                                }
                                trial = 0;
                                continue;
                            } else {
                                this.logger.crash('proxies_bad_config', this._logPrefix(), 'proxies url must be specified');
                            }
                        }
                    }
                    if (!ignoreRequestInterval) {
                        const waitInterval = this._nextTimeRequestProxyList - Date.now();
                        if (waitInterval > 0) {
                            this._info(logger, 'Wait ', waitInterval / 1000, ' seconds before refreshing proxy list through ', this._options.url);
                            await sleep(waitInterval);
                        }
                    }
                    this._info(logger, 'Refresh proxy list: ', this._options.url);
                    let resp, error, proxiesRequested = [];
                    const reqOptions = {uri: this._options.url, ...proxyTypes[this.type].requestOptions};
                    try {
                        resp = await this._request.instance(logger, reqOptions);
                    } catch (e) {
                        error = e;
                    }
                    this._nextTimeRequestProxyList = Date.now() + this._options.minIntervalBetweenRequest * 1000;
                    ignoreRequestInterval = false;
                    try {
                        proxiesRequested = await proxyTypes[this.type].requestParser({resp, error});
                    } catch (e) {
                        this._warn(
                            logger, 'Failed parsing proxy response from ', this._options.url, 
                            ' -> ', e, ' : ', {resp, error}
                        );
                        proxiesRequested = 'INVALID_URL';
                    }
                    if (proxiesRequested === 'INVALID_URL') {
                        if (this._options.allowNoProxy) {
                            this._warn(logger, this.name, ' url is invalid for refreshing proxy list: ', this._options.url);
                            return false;
                        } else {
                            if (this._stored) {
                                const message = `${this.name} url is invalid and need to be changed, ` +
                                    `requesting proxies returns ${resp ? JSON.stringify(resp) : error}.`;
                                const store = await this.logger.pull({
                                    waitUntil: s => {
                                        const url = get(s, [this.name, 'options', 'url']);
                                        return url && url !== this._options.url;
                                    },
                                    message
                                });
                                await this._load(store);
                                trial = 0;
                            } else {
                                this._crash(
                                    logger, 'proxies_invalid_url', 'Invalid url for refreshing proxy list ', 
                                    this._options.url, ' -> ', resp || error
                                );
                            }
                        }
                    } else if (proxiesRequested === 'REQUEST_TOO_FREQUENT') {
                        this._info(logger, 'It seems refreshing proxies too frequently, will re-try later: ', resp || error);
                    } else if (proxiesRequested === 'JUST_RETRY') {
                        this._info(logger, 'It seems refreshing proxies has some problems, will re-try immediately: ', resp || error);
                        ignoreRequestInterval = true;
                    } else {
                        let added = 0;
                        if (proxiesRequested && proxiesRequested !== 'UNKNOWN_ERROR') {
                            if (!Array.isArray(proxiesRequested)) {
                                proxiesRequested = [proxiesRequested];
                            }
                            for (let proxy of proxiesRequested) {
                                if (typeof proxy === 'string') {
                                    const [ip, port] = proxy.split(':');
                                    proxy = {ip, port};
                                }
                                const id = this._id(proxy);
                                this._proxies[id] = {...this._proxies[id], ...proxy};
                                added++;
                            }
                        }
                        if (added > 0) {
                            return true;
                        }
                        const errorMessage = proxiesRequested === 'UNKNOWN_ERROR' ? 'There is an unknown error' : 'No new proxies are added';
                        if (!(this._options.maxRetryRequest >= 0)) {
                            if (this._options.allowNoProxy) {
                                this._warn(
                                    logger, errorMessage, ' during refreshing proxy list from ', this._options.url,
                                    ': ', resp || error
                                );
                                return false;
                            } else {
                                this._fail(
                                    logger, 'proxies_refresh_error', errorMessage, ' during refreshing proxy list from ', this._options.url,
                                    ': ', resp || error
                                );
                            }
                        } else if (trial <= this._options.maxRetryRequest) {
                            this._warn(
                                logger, errorMessage, ' during refreshing proxy list from ', this._options.url,
                                ', will re-try (', trial, '/', this._options.maxRetryRequest, '): ', resp || error
                            );
                        } else {
                            if (this._options.allowNoProxy) {
                                this._warn(
                                    logger, errorMessage, ' during refreshing proxy list from ', this._options.url,
                                    ', and too many retries have been performed (',
                                    this._options.maxRetryRequest, '/', this._options.maxRetryRequest, '): ', resp || error
                                );
                                return false;
                            } else {
                                this._fail(
                                    logger, 'proxies_refresh_error', errorMessage, ' during refreshing proxy list from ', this._options.url,
                                    ', and too many retries have been performed (',
                                    this._options.maxRetryRequest, '/', this._options.maxRetryRequest, '): ', resp || error
                                );
                            }
                        }
                    }
                }
            }

            async get(logger, identity) {
                logger = logger || this.logger;
                this._purge(logger);
                let proxy = undefined, one = undefined;
                if (identity) {
                    for (const p of this._iterProxies()) {
                        if (p.identity === identity) {
                            proxy = p;
                        }
                    }
                }
                if (!proxy) {
                    proxy = await this._get(logger, identity);
                }
                if (proxy) {
                    one = this._str(proxy);
                    this._info(logger, one, ' is being used', identity ? ` for identity ${identity}` : '', '.');
                }
                return one;
            }

            async _get(logger, identity) {
                let load = true, proxy = undefined;
                while (!proxy && load) {
                    for (const p of this._iterProxies()) {
                        const {identityBlacklist} = p;
                        if (p.identity) continue;
                        if (identity && identityBlacklist && identityBlacklist.includes(identity)) continue;
                        if (p.lastTimeUsed > Date.now() - this._options.minIntervalBetweenUse * 1000) continue;
                        if (!proxy) {
                            proxy = p;
                        } else {
                            if (this._options.recentlyUsedFirst) {
                                if (p.lastTimeUsed > proxy.lastTimeUsed) {
                                    proxy = p;
                                }
                            } else {
                                if (p.lastTimeUsed < proxy.lastTimeUsed) {
                                    proxy = p;
                                }
                            }
                        }
                    }
                    if (!proxy) load = await this._requestProxyList(logger);
                }
                if (proxy) {
                    if (identity) {
                        proxy.identity = identity;
                        proxy.identityAssignedAt = new Date();
                    }
                    this.touch(logger, proxy);
                    this._syncStore();
                }
                return proxy;
            }

            touch(_, one) {
                const proxy = this._find(one);
                if (!proxy) return;
                proxy.lastTimeUsed = new Date();
                this._syncStore();
            }

            deprecate(logger, one, {clearIdentity = true} = {}) {
                const proxy = this._find(one);
                if (!proxy) return;
                proxy.deprecated = (proxy.deprecated || 0) + 1;
                this._info(
                    logger, this._str(proxy), ' is marked as deprecated (',
                    proxy.deprecated, '/', this._options.maxDeprecationsBeforeRemoval, ').'
                );
                if (proxy.deprecated >= this._options.maxDeprecationsBeforeRemoval) {
                    this.remove(logger, proxy);
                } else {
                    if (clearIdentity && proxy.identity) {
                        this._deprecateIdentity(proxy);
                    }
                }
                this._syncStore();
            }

            remove(logger, one) {
                const proxy = this._find(one);
                if (!proxy) return;
                this._proxies[this._id(proxy)] = null;
                this._info(logger, this._str(proxy), ' is removed: ', proxy);
                this._syncStore();
            }

            _find(one) {
                let id;
                if (typeof one === 'string') {
                    const [ip, port] = one.split(':');
                    if (port) {
                        id = this._id({ip, port});
                    } else {
                        id = ip;
                    }
                } else {
                    id = this._id(one);
                }
                return this._proxies[id];
            }

            * _iterProxies(proxies) {
                for (const proxy of Object.values(proxies || this._proxies)) {
                    if (!proxy) continue;
                    yield proxy;
                }
            }

            _purge(logger) {
                Object.entries(this._proxies)
                    .filter(([, p]) => !this._isValid(p))
                    .forEach(([id]) => this.remove(logger, id));
                for (const proxy of this._iterProxies()) {
                    if (this._isIdentityExpired(proxy)) {
                        this._clearIdentity(proxy);
                    }
                }
            }

            _deprecateIdentity(proxy) {
                if (!proxy.identityBlacklist) proxy.identityBlacklist = [];
                proxy.identityBlacklist.push(proxy.identity);
                this._clearIdentity(proxy);
            }
            
            _clearIdentity(proxy) {
                proxy.identity = undefined;
                proxy.identityAssignedAt = undefined;
            }

            async _syncStoreForce() {
                let deleteNullProxies = true;
                if (this._stored) {
                    try {
                        let store;
                        if (isEmpty(this._proxies)) {
                            store = await this.logger.pull();
                        } else {
                            store = await this.logger.push({[this.name]: {proxies: this._proxies}});
                        }
                        await this._load(store[this.name]);
                    } catch (e) {
                        deleteNullProxies = false;
                        this._warn(undefined, 'Sync proxies of name ', this.name, ' failed: ', e);
                    }
                }
                if (deleteNullProxies) {
                    Object.entries(this._proxies)
                        .filter(([, p]) => !p)
                        .forEach(([id]) => delete this._proxies[id]);
                }
            }

            _syncStore() {
                this._syncStoreForce().catch(e => console.error('This should never happen: ', e));
            }

            _id(proxy) {
                return `${proxy.ip.split('.').join('_')}__${proxy.port}`;
            }

            _str(proxy) {
                return `${proxy.ip}:${proxy.port}`;
            }

            _isValid(proxy) {
                if (!proxy) return false;
                return !this._isExpired(proxy) && !this._isDeprecated(proxy);
            }

            _isExpired(proxy) {
                const {expire} = proxy;
                return expire < Date.now();
            }

            _isDeprecated(proxy) {
                const {deprecated} = proxy;
                return deprecated >= this._options.maxDeprecationsBeforeRemoval;
            }

            _isIdentityExpired(proxy) {
                const {identity, identityAssignedAt} = proxy;
                return identity && identityAssignedAt < Date.now() - this._options.proxiesWithIdentityTTL * 1000;
            }

            _makeOptions(options) {
                return {
                    maxDeprecationsBeforeRemoval: 1, minIntervalBetweenUse: 0, recentlyUsedFirst: true,
                    minIntervalBetweenRequest: 5, minIntervalBetweenStoreUpdate: 10,
                    proxiesWithIdentityTTL: 24 * 60 * 60, maxRetryRequest: -1, allowNoProxy: true,
                    ...options
                };
            }
            
            _logPrefix() {
                return this.name ? `Proxies ${this.name}: ` : 'Proxies: ';
            }

            _info(logger, ...args) {
                (logger || this.logger).info(this._logPrefix(), ...args);
            }

            _warn(logger, ...args) {
                (logger || this.logger).warn(this._logPrefix(), ...args);
            }
            
            _fail(logger, code, ...args) {
                (logger || this.logger).fail(code, this._logPrefix(), ...args);
            }

            _crash(logger, code, ...args) {
                (logger || this.logger).crash(code, this._logPrefix(), ...args);
            }
            
            async _unload(job) {
                if (this._request) {
                    await this._request.unload(job);
                }
            }

            async _destroy() {
                await this._syncStoreForce();
                if (this._request) {
                    await this._request.destroy();
                }
            }

        }

        return {
            key({name}) {
                return name;
            },
            async create({name, type, options, stored = false, dummy}, {pluginLoader}) {
                if (dummy) {
                    return new Dummy(dummy);
                } else {
                    const proxies = new Proxies(this, name, pluginLoader, {stored});
                    await proxies._init({type, options});
                    return proxies;
                }
            },
            async unload(proxies, job) {
                await proxies._unload(job);
            },
            async destroy(proxies) {
                await proxies._destroy();
            }
        };
    }
};
