/* 
 * Copyright (c) 2015 Restful Design (restfuldesign.com), all rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*global require console module Buffer */

module.exports = (function(root) {
    "use strict";

    var https = require('https');
    var HTTP_ERROR = require('http').STATUS_CODES;

    var crypto = require('crypto');
    var querystring = require('querystring');


    function PandaError(code, error, message, data) {
        if (Error.captureStackTrace)
            Error.captureStackTrace(this, this.constructor);

        this.name = 'panda_error';

        if (error == undefined && isNaN(code)) {
            error = code;
        }

        if (typeof error === 'object') {
            this.code = error.code;
            this.error = error.error;
            this.message = error.message;
            this.data = error.data;
        } else {
            this.code = code;
            this.error = error;
            this.message = message;
            this.data = data;
        }
    }

    PandaError.prototype = Object.create(Error.prototype);
    PandaError.prototype.constructor = PandaError;

    var ERROR = {
        TYPE: {
            code: 1,
            error: 'type error',
            message: 'invalid type'
        },
        OPTIONS: {
            code: 1,
            error: 'type error',
            message: 'missing or invalid options object'
        },
        SHOP: {
            code: 1,
            error: 'type error',
            message: 'shop must be a hostname string'
        },
        CALLBACK: {
            code: 1,
            error: 'type error',
            message: 'callback must be a function'
        },
        LOGGER: {
            code: 1,
            error: 'type error',
            message: 'logger must be a function'
        },
        OAUTH: {
            code: 1,
            error: 'type error',
            message: 'oauth must be an object'
        },
        STREAM: {
            code: 1,
            error: 'type error',
            message: 'missing or invalid stream class'
        },
        PARAMS: {
            code: 4,
            error: 'type error',
            message: 'missing parameters object'
        },
        OAUTH_SCOPE: {
            code: 2,
            error: 'oauth error',
            message: 'missing or invalid oauth scope'
        },
        OAUTH_API_KEY: {
            code: 2,
            error: 'oauth error',
            message: 'missing or invalid oauth api_key'
        },
        OAUTH_PRIVATE_KEY: {
            code: 2,
            error: 'oauth error',
            message: 'missing or invalid oauth private_key'
        },
        OAUTH_SIGNATURE: {
            code: 2,
            error: 'oauth error',
            message: 'oauth signature mismatch'
        },
        OAUTH_SHARED_SECRET: {
            code: 2,
            error: 'oauth error',
            message: 'missing or invalid oauth shared_secret'
        },
        TIMEOUT: {
            code: 3,
            error: 'timeout error',
            message: 'operation timed out'
        },
        SIGNATURE_PARAM: {
            code: 4,
            error: 'params error',
            message: 'missing or invalid signature'
        },
        CODE_PARAM: {
            code: 4,
            error: 'params error',
            message: 'missing or invalid code'
        }
    };

    function PandaAPI(options) {
        options = options || {};

        if (!(this instanceof PandaAPI))
            return new PandaAPI(options);

        this.debug = !!options.debug;

        if (this.debug) {
            if (options.logger && typeof options.logger !== 'function')
                throw new PandaError(ERROR.LOGGER);

            this.logger = options.logger || console.log;
        }

        this.shop = options.shop || '';
        this.oauth = options.oauth || {};
        this.port = options.port || 443;

        this.httpsAgent = new https.Agent({
            keepAlive: options.keepAlive || true,
            maxSockets: options.maxSockets || 4
        });
    }

    PandaAPI.prototype = {
        "logger": function() {},
        "getAuthURL": function() {
            var url = 'https://';

            if (!this.shop || typeof this.shop !== 'string')
                throw new PandaError(ERROR.SHOP);

            url += this.shop;
            url += '/admin/oauth/authorize?';

            if (!this.oauth.api_key)
                throw new PandaError(ERROR.OAUTH_API_KEY);

            url += 'client_id=' + this.oauth.api_key;

            if (!this.oauth.scope)
                throw new PandaError(ERROR.OAUTH_SCOPE);

            url += '&scope=' + this.oauth.scope;
            url += '&response_type=code';

            if (this.oauth.redirect_uri) {
                url += '&redirect_uri=' + this.oauth.redirect_uri;
            }

            return url;
        },
        "setAccessToken": function(token) {
            if (typeof this.oauth !== 'object')
                throw new PandaError(ERROR.OAUTH);

            this.oauth.access_token = token;
        },
        "urlQuerystring": function(url, query) {
            var uri;

            if (query == undefined) return querystring.parse(url);

            var q = (url.indexOf('?') >= 0 ? '&' : '?');

            if (typeof query === 'string') uri = q + query;
            else uri = q + querystring.stringify(query);

            url += uri;

            return url;
        },
        "validateSignature": function(params) {
            var signature,
                secret,
                parameters = [],
                digest,
                message;

            if (typeof params !== 'object')
                throw new PandaError(ERROR.PARAMS);

            if (!params['signature'])
                throw new PandaError(ERROR.SIGNATURE_PARAM);

            signature = params['signature'];

            if (!this.oauth.shared_secret)
                throw new PandaError(ERROR.OAUTH_SHARED_SECRET);

            secret = this.oauth.shared_secret;

            for (var key in params) {
                if (key != 'signature') {
                    parameters.push(key + '=' + params[key]);
                }
            }

            message = secret + parameters.sort().join('');

            digest = crypto.createHash('md5').update(message).digest('hex');

            return (digest === signature);
        },
        "getAccessTokenFromCode": function(code, callback) {
            var data, self = this;

            if (typeof code !== 'string')
                throw new PandaError(ERROR.CODE_PARAM);
            
            if (typeof callback !== 'function')
                throw new PandaError(ERROR.CALLBACK);
            
            if (!this.oauth.api_key)
                throw new PandaError(ERROR.OAUTH_API_KEY);

            if (!this.oauth.private_key)
                throw new PandaError(ERROR.OAUTH_PRIVATE_KEY);

            data = {
                client_id: this.oauth.api_key,
                client_secret: this.oauth.private_key,
                code: code,
                grant_type: 'authorization_code'
            };

            this.post('/admin/oauth/token.json', data, function(err, ret) {

                if (err) {
                    callback(err, ret);
                } else {
                    self.setAccessToken(ret['access_token']);
                    callback(undefined, ret);
                }
            });

            return this;
        },
        "exchangeToken": function(params, callback) {
            var data, error;

            if (typeof callback !== 'function')
                throw new PandaError(ERROR.CALLBACK);

            if (!this.validateSignature(params)) {
                callback(new PandaError(ERROR.OAUTH_SIGNATURE));
            } else {
                this.getAccessTokenFromCode(params['code'], callback);
            }

            return this;
        },
        request: function(method, path, data, options, callback) {
            var request = https.request,
                encoding = 'utf8',
                self = this,
                transmit,
                o = {};

            this.logger("request:", method, path);

            if (['get', 'head'].indexOf(method) >= 0) {
                callback = options;
                options = data;
            }

            if (typeof options === 'function') {
                callback = options;
                options = undefined;
            }

            if (typeof data === 'function') {
                callback = data;
                data = undefined;
            }

            options = options || {};

            o.method = method || 'get';
            o.agent = this.httpsAgent;
            o.hostname = this.shop;
            o.port = this.port;
            o.path = path;
            o.headers = {};

            o.headers['accept'] = 'application/json';

            if (!options.readable) {
                if (data && typeof data !== 'string')
                    data = JSON.stringify(data);
                
                o.headers['content-type'] = 'application/json';
                o.headers['content-length'] = data ? Buffer.byteLength(data) : 0;
            } else {
                o.headers['transfer-encoding'] = 'chunked';
            }

            if (this.oauth.access_token)
                o.headers['api-access-token'] = this.oauth.access_token;

            if (options.headers != undefined) {
                for (var key in options.headers)
                    o.headers[key] = options.headers[key];
            }

            if (options.encoding)
                encoding = options.encoding;

            if(options.writable)
                transmit = requestStream(request,o,data);
            else
                transmit = requestCallback(request,o,callback);

            if (options.timeout != undefined) {
                transmit.on('socket', function(socket) {
                    socket.setTimeout(options.timeout);

                    socket.on('timeout', function() {
                        if (callback) callback(new PandaError(ERROR.TIMEOUT));
                        transmit.abort();
                    });
                });
            }

            transmit.on('error', function(error) {
                if (options.readable || options.writable) {
                    if (!data && !data.on && typeof data.on !== 'function')
                        throw new PandaError(ERROR.STREAM);

                    data.emit('error', error);
                }

                if (callback) callback(error);
                else throw new PandaError(error);
            });


            if (options.readable) {
                if (!data && !data.pipe && typeof data.pipe !== 'function')
                    throw new PandaError(ERROR.STREAM);

                data.pipe(transmit);
            } else {
                transmit.end(data, encoding);
            }

        }
    };

    function requestStream(request,options,stream){
        if (!stream && !stream.on && typeof stream.on !== 'function')
            throw new PandaError(ERROR.STREAM);

        var req = request(options);

        req.on('response', function(message) {
            var statusCode = message.statusCode,
                statusMessage = message.statusMessage;

            if (statusCode && statusCode < 400) {
                message.pipe(stream);
            } else {
                stream.emit('error', new PandaError({
                    code: statusCode,
                    error: HTTP_ERROR[statusCode],
                    message: statusMessage,
                    data: message
                }));
            }

            message.on('error', function(error) {
                stream.emit('error', error);
            });
        });

        return req;
    }

    function requestCallback(request,options,callback){
        var req = request(options, function(response) {
            var buffer = [];

            response.on('data', function(chunk) {
                buffer.push(chunk);
            }).on('end', function() {
                var headers = response.headers || {},
                    result = result = buffer.join(''),
                    statusCode = response.statusCode,
                    contentType = headers['content-type'];

                if (contentType.indexOf('json') >= 0) {
                    result = JSON.parse(result);
                }

                if (statusCode && statusCode < 400) {
                    callback(undefined, result);
                } else {
                    callback(new PandaError({
                        code: statusCode,
                        error: HTTP_ERROR[statusCode],
                        message: JSON.stringify(result),
                        data: result
                    }), response);
                }

            }).on('error', function(error) {
                callback(error, response);
            });
        });
    }
    
    // request methods
    ['head', 'get', 'put', 'post', 'delete', 'patch', 'trace', 'connect', 'options']
        .forEach(function(method) {
            PandaAPI.prototype[method] = function(url, data, opt, res) {
                return this.request(method, url, data, opt, res);
            };
        });

    return PandaAPI;

})(this);
