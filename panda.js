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

    var Stream = require('stream');
    var Readable = Stream.Readable || require('readable-stream').Readable;
    var Writable = Stream.Writable || require('readable-stream').Writable;
    var Duplex = Stream.Duplex || require('readable-stream').Duplex;

    function PandaError(code, error, message, data) {
        this.name = 'panda_error';

        if (error == undefined && isNaN(code)) {
            error = code;
        }

        if (isObject(error)) {
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
        CONFIG_OPTIONS: {
            code: 1,
            error: 'config error',
            message: 'missing options'
        },
        CONFIG_SHOP: {
            code: 2,
            error: 'config error',
            message: 'missing or invalid shop name'
        },
        CONFIG_OAUTH: {
            code: 3,
            error: 'config error',
            message: 'missing or invalid oauth settings'
        },
        OAUTH_SIGNATURE: {
            code: 4,
            error: 'oauth error',
            message: 'signature mismatch'
        }
    };

    function PandaAPI(options) {

        if (!(this instanceof PandaAPI))
            return new PandaAPI(options);

        if (options == undefined)
            throw new PandaError(ERROR.CONFIG_OPTIONS);

        if (typeof options.shop !== 'string')
            throw new PandaError(ERROR.CONFIG_SHOP);

        if (options.oauth == undefined)
            throw new PandaError(ERROR.CONFIG_OAUTH);

        this.oauth = options.oauth;
        this.debug = !!options.debug;
        this.shop = options.shop.split('.')[0];
        this.host = options.host || 'pandacommerce.net';
        this.port = options.port || 443;
        this.hostname = this.shop + '.' + this.host;

        this.httpsAgent = new https.Agent({
            keepAlive: options.keepAlive || true,
            maxSockets: options.maxSockets || 4
        });

        // used for debugging
        this.logger = this.debug ? (options.logger || console.log) : function() {};
    }

    PandaAPI.prototype = {
        "getAuthURL": function() {
            var url = 'https://' + this.hostname;

            url += '/admin/oauth/authorize?';
            url += 'client_id=' + this.oauth.api_key;
            url += '&scope=' + this.oauth.scope;
            url += '&response_type=code';
            url += '&redirect_uri=' + this.oauth.redirect_uri;

            return url;
        },
        "setAccessToken": function(token) {
            this.oauth.access_token = token;
        },
        "urlQuery": function(url, query) {
            var uri;

            if (query == undefined) return querystring.parse(url);

            var q = (url.indexOf('?') >= 0 ? '&' : '?');

            if (typeof query === 'string') uri = q + query;
            else uri = q + querystring.stringify(query);

            url += uri;

            return url;
        },
        "validateSignature": function(params) {
            var signature = params['signature'],
                secret = this.oauth.shared_secret,
                parameters = [],
                digest,
                message;

            for (var key in params) {
                if (key != 'signature') {
                    parameters.push(key + '=' + params[key]);
                }
            }

            message = secret + parameters.sort().join('');

            digest = crypto.createHash('md5').update(message).digest('hex');

            return (digest === signature);
        },
        "exchangeToken": function(params, callback) {
            var data, error;

            if (!this.validateSignature(params)) {
                error = new PandaError(ERROR.OAUTH_SIGNATURE);

                if (callback) callback(error);
                else throw error;

                return;
            }

            data = {
                client_id: this.oauth.api_key,
                client_secret: this.oauth.private_key,
                code: params['code'],
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
        },
        request: function(method, path, data, options, callback) {
            var request = https.request,
                readable = false,
                writable = false,
                encoding = 'utf8',
                self = this,
                transmit,
                o = {};

            this.logger("%s", method, path);

            if (typeof options === 'function') {
                callback = options;
                options = undefined;
            }

            if (typeof data === 'function') {
                callback = data;
                data = undefined;
            }

            if ((data instanceof Stream)) readable = true;
            if ((data instanceof Writable)) writable = true;
            else if ((data instanceof Duplex)) writable = true;

            o.method = method || 'get';
            o.agent = this.httpsAgent;
            o.hostname = this.hostname;
            o.port = this.port;
            o.path = path;
            o.headers = {};

            o.headers['accept'] = 'application/json';

            if (readable) {
                o.headers['transfer-encoding'] = 'chunked';
            }

            if (!readable) {
                o.headers['content-type'] = 'application/json';
                o.headers['content-length'] = data ? Buffer.byteLength(data) : 0;

                if (data && typeof data !== 'string')
                    data = JSON.stringify(data); // note: throws on error
            }

            if (this.oauth.access_token) {
                o.headers['api-access-token'] = this.oauth.access_token;
            }

            if (typeof options === 'object') {
                if (options.timeout != undefined) {
                    request.socket.setTimeout(options.timeout);
                }

                if (options.headers != undefined) {
                    extend(o.headers, options.headers);
                }

                if (options.encoding) encoding = options.encoding;
            }

            if (writable) {
                transmit = request(o).on('response', function(message) {
                    if (message.statusCode < 400) {
                        data.emit('open', message);
                    } else {
                        data.emit('error', message);
                    }
                });
            } else {
                transmit = request(o, function(response) {
                    var buffer = [];

                    response.on('data', function(chunk) {
                        buffer.push(chunk);
                    }).on('end', function() {
                        var headers = response.headers || {},
                            result = result = buffer.join('');

                        self.logger("statusCode %d, content-type", response.statusCode, headers['content-type']);

                        if (headers['content-type'].indexOf('json') >= 0) {
                            result = JSON.parse(result);
                        }

                        self.logger("response: %j", JSON.stringify(result, null, 1));

                        if (response.statusCode < 400) {
                            callback(undefined, result);
                        } else {

                            callback(new PandaError({
                                code: response.statusCode,
                                error: HTTP_ERROR[response.statusCode],
                                message: JSON.stringify(result),
                                data: result
                            }), response);
                        }

                    }).on('error', function(error) {
                        callback(error, response);
                    });
                });
            }

            transmit.on('error', function(error) {
                if (readable || writable) data.emit('error', error);
                if (callback) callback(error);
                else throw new PandaError(error);
            });


            if (readable) {
                data.pipe(transmit);
            } else {
                transmit.end(data, encoding);
            }

        }

    };

    // request methods
    ['head', 'get', 'put', 'post', 'delete', 'patch', 'trace', 'connect', 'options']
        .forEach(function(method) {
            PandaAPI.prototype[method] = function(url, data, opt, res) {
                return this.request(method, url, data, opt, res);
            };
        });


    // utility functions
    function isObject(o) {
        return (
            typeof o === 'object' &&
            o !== null &&
            !Array.isArray(o)
        );
    }

    // extends object
    function extend() {
        var source,
            target,
            deep = false,
            args = Array.prototype.slice.call(arguments),
            argc = args.length,
            arg = 0;

        if (typeof args[0] === "boolean") deep = args[arg++];

        target = args[arg++];

        if (argc <= arg) return extend(deep, {}, target);

        while (arg < argc) {
            source = args[arg++];

            if (!isObject(source)) continue;

            Object.keys(source).forEach(function(key) {
                var from = source[key],
                    to = target[key];

                if (deep && isObject(from)) {
                    if (target.hasOwnProperty(key) && isObject(to)) {
                        extend(true, target[key], from);
                    } else {
                        target[key] = extend(true, {}, from);
                    }
                } else if (from !== undefined) {
                    target[key] = from;
                }
            });
        }

        return target;
    }


    return PandaAPI;

})(this);
