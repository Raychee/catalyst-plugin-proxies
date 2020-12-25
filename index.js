const {get, setWith, isEmpty} = require('lodash');
const {dedup, limit} = require('@raychee/utils');


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

                this._pluginLoader = pluginLoader;
                this._stored = stored;
                this._proxies = {};
                this._identities = {};
                this._type = undefined;
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
                            'plugin_proxies_invalid_name', 'invalid proxies name: ', this.name, ', please make sure: ',
                            '1. there is a document in the internal collection service.Store that matches filter {plugin: \'proxies\'}, ',
                            '2. there is a valid entry under document field \'data.', this.name, '\''
                        );
                    }
                }
                await this._load(store);
            }

            async _load(store = {}) {
                const {type, options, proxies = {}, identities = {}} = store;
                const {minIntervalBetweenStoreUpdate} = this._options || {};
                this._options = this._makeOptions(options);
                if (minIntervalBetweenStoreUpdate !== this._options.minIntervalBetweenStoreUpdate) {
                    this._syncStoreForce = dedup(
                        Proxies.prototype._syncStoreForce.bind(this),
                        {within: this._options.minIntervalBetweenStoreUpdate * 1000, queue: 1}
                    );
                }
                if (type) this._type = type;
                if (!proxyTypes[this._type]) {
                    this.logger.crash('plugin_proxies_bad_config', this._logPrefix(), 'unknown proxies type: ', this._type);
                }
                if (this._request) {
                    await this._request.destroy();
                }
                this._request = await this._pluginLoader.get({type: 'request', ...this._options.request});
                for (const proxy of this._iterProxies(proxies)) {
                    const id = this._id(proxy);
                    this._proxies[id] = {...proxy, ...this._proxies[id]};
                }
                for (const [id, identity] of Object.entries(identities)) {
                    this._identities[id] = {...identity, ...this._identities[id]};
                }
            }
            
            _makeOptions(options) {
                return {
                    maxDeprecationsBeforeRemoval: 1, minIntervalBetweenUse: 0, recentlyUsedFirst: true,
                    minIntervalBetweenRequest: 5, minIntervalBetweenStoreUpdate: 10,
                    proxiesWithIdentityTTL: 24 * 60 * 60, maxRetryRequest: -1, allowNoProxy: true,
                    identityWithoutProxyTTL: 24 * 60 * 60, 
                    identityLocationPreferred: true, identityLocationConstrained: false,
                    identityHistoricalLocationPreferred: true,
                    // request: {},
                    ...options
                };
            }

            async get(logger, {id, location} = {}, options = {}) {
                logger = logger || this.logger;
                options = {...this._options, ...options};
                let historicalLocation = undefined;
                this._purge(logger);
                let proxy = undefined;
                if (id) {
                    const p = get(this._identities, [id, 'proxy']);
                    historicalLocation = get(this._identities, [id, 'location']);
                    proxy = this._proxies[p];
                    if (!proxy) {
                        for (const p of this._iterProxies()) {
                            if (p.identity === id) {
                                proxy = p;
                            }
                        }
                    }
                }
                const locationPreference = Object.fromEntries((
                    options.identityHistoricalLocationPreferred ? 
                        [historicalLocation, location] : [location, historicalLocation])
                    .filter(l => l).map((l, precedence) => [l, precedence]).reverse()
                );
                if (!proxy) {
                    const prioritizedLocations = Object.entries(locationPreference)
                        .sort((a, b) => a[1] - b[1])
                        .map(([l]) => l);
                    this._info(
                        logger, 'Get a proxy', ...(id ? [' for identity ', id] : []),
                        ...(!isEmpty(locationPreference) ? [
                            ' with location ', 
                            ...(options.identityLocationConstrained ? 
                                ['constraint: ', prioritizedLocations[0]] : 
                                ['preference: ', prioritizedLocations.join(', ')]
                            )
                        ] : []), '.'
                    );
                    let load = true;
                    while (!proxy && load) {
                        for (const p of this._iterProxies()) {
                            const {identityBlacklist} = p;
                            if (p.identity) continue;
                            if (id && identityBlacklist && identityBlacklist.includes(id)) continue;
                            if (p.lastTimeUsed > Date.now() - options.minIntervalBetweenUse * 1000) continue;
                            if (id && get(this._identities, [id, 'proxyBlacklist'], []).includes(this._id(p))) continue;
                            if (!isEmpty(locationPreference)) {
                                const thisPreference = p.location && locationPreference[p.location];
                                if (options.identityLocationConstrained && thisPreference !== 0) continue;
                                if (options.identityLocationPreferred) {
                                    const existingPreference = proxy && proxy.location && locationPreference[proxy.location];
                                    if (
                                        existingPreference == null && thisPreference != null || 
                                        existingPreference > thisPreference
                                    ) {
                                        proxy = undefined;
                                    } else if (
                                        existingPreference != null && thisPreference == null ||
                                        existingPreference < thisPreference
                                    ) {
                                        continue;
                                    }
                                }
                            }
                            if (!proxy) {
                                proxy = p;
                            } else {
                                if (options.recentlyUsedFirst) {
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
                }
                if (proxy) {
                    if (id) {
                        proxy.identity = id;
                        proxy.identityAssignedAt = new Date();
                        setWith(this._identities, [id, 'proxy'], this._id(proxy), Object);
                        setWith(this._identities, [id, 'lastTimeAssignedProxy'], new Date(), Object);
                        setWith(this._identities, [id, 'location'], proxy.location || null, Object);
                    }
                    this.touch(logger, proxy);
                    const one = this._str(proxy);
                    this._info(
                        logger, one, ...(proxy.location ? [' (', proxy.location, ')'] : []),
                        ' is being used', ...(id ? [' for identity ', id] : []), '.'
                    );
                    return one;
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
                                this.logger.crash('plugin_proxies_bad_config', this._logPrefix(), 'proxies url must be specified');
                            }
                        }
                    }
                    if (!ignoreRequestInterval) {
                        const waitInterval = (this._nextTimeRequestProxyList - Date.now()) / 1000;
                        if (waitInterval > 0) {
                            this._info(logger, 'Wait ', waitInterval, ' seconds before refreshing proxy list through ', this._options.url);
                            await logger.sleep(waitInterval);
                        }
                    }
                    this._info(logger, 'Refresh proxy list: ', this._options.url);
                    let resp, error, proxiesRequested = [];
                    const reqOptions = {uri: this._options.url, ...proxyTypes[this._type].requestOptions};
                    try {
                        resp = await this._request.instance(logger, reqOptions);
                    } catch (e) {
                        error = e;
                    }
                    this._nextTimeRequestProxyList = Date.now() + this._options.minIntervalBetweenRequest * 1000;
                    ignoreRequestInterval = false;
                    try {
                        proxiesRequested = await proxyTypes[this._type].requestParser({resp, error});
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
                                    logger, 'plugin_proxies_invalid_url', 'Invalid url for refreshing proxy list ',
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
                            this._info(logger, added, ' proxies are added from ', this._options.url);
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
                                    logger, 'plugin_proxies_refresh_error', errorMessage, ' during refreshing proxy list from ', this._options.url,
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
                                    logger, 'plugin_proxies_refresh_error', errorMessage, ' during refreshing proxy list from ', this._options.url,
                                    ', and too many retries have been performed (',
                                    this._options.maxRetryRequest, '/', this._options.maxRetryRequest, '): ', resp || error
                                );
                            }
                        }
                    }
                }
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
                    proxy.deprecated, '/', 
                    this._options.maxDeprecationsBeforeRemoval >= 0 ? this._options.maxDeprecationsBeforeRemoval : '∞', 
                    ').'
                );
                if (this._isDeprecated(proxy)) {
                    this.remove(logger, proxy);
                } else {
                    if (clearIdentity) {
                        this._deprecateIdentity(proxy);
                    }
                }
                this._syncStore();
            }

            remove(logger, one, {clearIdentity = true} = {}) {
                const proxy = this._find(one);
                if (!proxy) return;
                this._proxies[this._id(proxy)] = null;
                this._info(logger, this._str(proxy), ' is removed: ', proxy);
                if (clearIdentity) {
                    this._deprecateIdentity(proxy, {proxyRemoved: true});
                }
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

            * _iterIdentities(identities) {
                for (const identity of Object.values(identities || this._identities)) {
                    if (!identity) continue;
                    yield identity;
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
                Object.entries(this._identities)
                    .filter(([, i]) => i && this._isIdentityWithoutProxyExpired(i))
                    .forEach(([id, i]) => {
                        this._info(logger, 'purge: ', id, ' - ', i);
                        this._identities[id] = null;
                    });
                for (const identity of this._iterIdentities()) {
                    if (identity.proxy && !this._proxies[identity.proxy]) {
                        this._clearIdentityProxy(identity);
                    }
                    if (identity.proxyBlacklist) {
                        identity.proxyBlacklist = identity.proxyBlacklist.filter(p => this._proxies[p]); 
                    }
                    if (this._isIdentityProxyExpired(identity)) {
                        this._clearIdentityProxy(identity);
                    }
                }
            }

            _deprecateIdentity(proxy, {proxyRemoved} = {}) {
                if (proxy.identity) {
                    if (!proxy.identityBlacklist) proxy.identityBlacklist = [];
                    proxy.identityBlacklist.push(proxy.identity);
                }
                this._clearIdentity(proxy);
                const p = this._id(proxy);
                for (const identity of this._iterIdentities()) {
                    if (identity.proxy !== p) continue;
                    if (proxyRemoved) {
                        if (identity.proxyBlacklist) {
                            identity.proxyBlacklist = identity.proxyBlacklist.filter(pb => pb !== p);
                        }
                    } else {
                        if (!identity.proxyBlacklist) identity.proxyBlacklist = [];
                        identity.proxyBlacklist.push(p);
                    }
                    this._clearIdentityProxy(identity);
                }
            }
            
            _clearIdentity(proxy) {
                proxy.identity = null;
                proxy.identityAssignedAt = null;
            }
            
            _clearIdentityProxy(identity) {
                identity.proxy = null;
                identity.lastTimeAssignedProxy = new Date();
            }

            async _syncStoreForce() {
                let deleteNulls = true;
                if (this._stored) {
                    try {
                        let store;
                        if (isEmpty(this._proxies)) {
                            store = await this.logger.pull();
                        } else {
                            store = await this.logger.push({
                                [this.name]: {proxies: this._proxies, identities: this._identities}
                            });
                        }
                        await this._load(store[this.name]);
                    } catch (e) {
                        deleteNulls = false;
                        this._warn(undefined, 'Sync proxies of name ', this.name, ' failed: ', e);
                    }
                }
                if (deleteNulls) {
                    Object.entries(this._proxies)
                        .filter(([, p]) => !p)
                        .forEach(([id]) => delete this._proxies[id]);
                    Object.entries(this._identities)
                        .filter(([, i]) => !i)
                        .forEach(([id]) => delete this._identities[id]);
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
                return this._options.maxDeprecationsBeforeRemoval >= 0 && deprecated >= this._options.maxDeprecationsBeforeRemoval;
            }

            _isIdentityExpired(proxy) {
                const {identity, identityAssignedAt} = proxy;
                return identity && identityAssignedAt < Date.now() - this._options.proxiesWithIdentityTTL * 1000;
            }
            
            _isIdentityProxyExpired(identity) {
                const {proxy, lastTimeAssignedProxy} = identity;
                return proxy && lastTimeAssignedProxy < Date.now() - this._options.proxiesWithIdentityTTL * 1000;
            }
            
            _isIdentityWithoutProxyExpired(identity) {
                const {proxy, lastTimeAssignedProxy} = identity;
                return !proxy && lastTimeAssignedProxy < Date.now() - this._options.identityWithoutProxyTTL * 1000; 
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
