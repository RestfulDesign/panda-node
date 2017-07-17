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

/*global require console module Buffer setTimeout */

module.exports = (function(root) {
    "use strict";

    var Errors = require('./errors');
    var PandaError = Errors.PandaError;
    var HttpError = Errors.HttpError;
    var PANDA_ERROR = PandaError.ERROR;
    
    var https = require('https');
    var HTTP_ERROR = require('http').STATUS_CODES;

    var crypto = require('crypto');
    var querystring = require('querystring');

    var LIMIT_WAIT = 500; // retry interval on http error 429 (api limit)
    
    function PandaAPI(options) {
        options = options || {};

        if (!(this instanceof PandaAPI))
            return new PandaAPI(options);

        this.hostname = options.hostname || options.shop || '';
        this.oauth = options.oauth || {};
        this.port = options.port || 443;
        
        this.authorization_url = this.oauth.authorization_url || '/admin/oauth/authorize';
        this.accesstoken_url = this.oauth.accesstoken_url || '/admin/oauth/token.json';
        if(!this.oauth.scope) this.oauth.scope = '';

        this.httpsAgent = new https.Agent({
            keepAlive: options.keepAlive || true,
            maxSockets: options.maxSockets || 4
        });

        if (options.logger) {
            if(typeof options.logger !== 'function')
                throw new PandaError(PANDA_ERROR.LOGGER);

            this.logger = options.logger;
        }
    }

    PandaAPI.prototype = {
        "logger": function() {},
        "getAuthURL": function() {
            var url = 'https://' + this.hostname;

            url += this.authorization_url + '?';

            if (!this.oauth.api_key)
                throw new PandaError(PANDA_ERROR.OAUTH_API_KEY);

            url += 'client_id=' + this.oauth.api_key;
            
            if(this.oauth.scope) {
                if (typeof this.oauth.scope !== 'string')
                    throw new PandaError(PANDA_ERROR.OAUTH_SCOPE);

                url += '&scope=' + this.oauth.scope;
            }
            
            url += '&response_type=code';

            if (this.oauth.redirect_uri) {
                url += '&redirect_uri=' + this.oauth.redirect_uri;
            }

            return url;
        },
        "setAccessToken": function(token) {
            if (typeof this.oauth !== 'object')
                throw new PandaError(PANDA_ERROR.OAUTH);

            this.oauth.access_token = token;

            return this;
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
                throw new PandaError(PANDA_ERROR.PARAMS);

            if (!params['signature'])
                throw new PandaError(PANDA_ERROR.SIGNATURE_PARAM);

            signature = params['signature'];

            if (!this.oauth.shared_secret)
                throw new PandaError(PANDA_ERROR.OAUTH_SHARED_SECRET);

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
            var data, url, self = this;

            if (typeof code !== 'string')
                throw new PandaError(PANDA_ERROR.CODE_PARAM);
            
            if (typeof callback !== 'function')
                throw new PandaError(PANDA_ERROR.CALLBACK);
            
            if (!this.oauth.api_key)
                throw new PandaError(PANDA_ERROR.OAUTH_API_KEY);

            if (!this.oauth.private_key)
                throw new PandaError(PANDA_ERROR.OAUTH_PRIVATE_KEY);

            data = {
                client_id: this.oauth.api_key,
                client_secret: this.oauth.private_key,
                code: code,
                grant_type: 'authorization_code'
            };

            url = this.accesstoken_url;

            return this.post(url, data, function(err, ret) {

                if (err) {
                    callback(err, ret);
                } else {
                    self.setAccessToken(ret['access_token']);
                    callback(undefined, ret);
                }
            });
        },
        "exchangeToken": function(params, callback) {
            var data, error;

            if (typeof callback !== 'function')
                throw new PandaError(PANDA_ERROR.CALLBACK);

            if (!this.validateSignature(params)) {
                callback(new PandaError(PANDA_ERROR.OAUTH_SIGNATURE));
            } else {
                this.getAccessTokenFromCode(params['code'], callback);
            }

            return this;
        },
        request: function(method, path, data, options, callback) {
            
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

            options.method = method || 'get';
            options.agent = this.httpsAgent;
            options.hostname = this.hostname;
            options.port = this.port;
            options.path = path;
            options.headers = options.headers || {};
            options.encoding = options.encoding || 'utf8';

            if(!options.headers['accept'])
                options.headers['accept'] = 'application/json';

            if (!options.readable) {
                if (data && typeof data !== 'string')
                    data = JSON.stringify(data);

                if(!options.headers['content-type'])
                    options.headers['content-type'] = 'application/json';

                if(!options.headers['content-length'])
                    options.headers['content-length'] = data ? Buffer.byteLength(data) : 0;
                
            } else {
                options.headers['transfer-encoding'] = 'chunked';
            }

            if (this.oauth.access_token)
                options.headers['api-access-token'] = this.oauth.access_token;

            if(options.writable) {
                if (!data || !data.on) {
                    throw new PandaError(PANDA_ERROR.STREAM);
                }                
                requestStream(options,data);
            } else {
                requestMethod(options,data,callback);
            }
                                            
            return this;
        }
    };

    function requestStream(options,stream,retry_count){
                
        var request = https.request(options);

        if(retry_count === undefined) retry_count = 0;

        request.on('response', function(message) {
            var statusCode = message.statusCode,
                statusMessage = message.statusMessage;

            if (statusCode && statusCode < 400) {
                message.pipe(stream);
            } else if (statusCode === 429 && retry_count <3){
                setTimeout(function(){
                    retry_count++;
                    requestStream(options,stream,retry_count);
                },LIMIT_WAIT);
            } else {
                stream.emit('error', new HttpError(
                    statusCode,
                    HTTP_ERROR[statusCode],
                    statusMessage,
                    message
                ));
            }

            message.on('error', function(error) {
                stream.emit('error', error);
            });
        }).on('error', function(error) {
            stream.emit('error',error);
        });

        if (options.timeout != undefined) {
            request.on('socket', function(socket) {
                socket.setTimeout(options.timeout);

                socket.on('timeout', function() {
                    stream.emit('error',new PandaError(PANDA_ERROR.TIMEOUT));
                    request.abort();
                });
            });
        }
    }

    function requestMethod(options,data,callback,retry_count){
        var request;

        if(retry_count === undefined) retry_count = 0;
        
        request = https.request(options, function(response) {
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
                } else if (statusCode === 429 && retry_count <3){
                    setTimeout(function(){
                        retry_count++;
                        requestMethod(options,data,callback,retry_count);
                    },LIMIT_WAIT);
                } else {                    
                    callback(new HttpError(
                        statusCode,
                        HTTP_ERROR[statusCode],
                        JSON.stringify(result),
                        result
                    ), response);
                }

            }).on('error', callback);
        }).on('error', callback);        

        if (options.timeout != undefined) {
            request.on('socket', function(socket) {
                socket.setTimeout(options.timeout);

                socket.on('timeout', function() {
                    callback(new PandaError(PANDA_ERROR.TIMEOUT));
                    request.abort();
                });
            });
        }

        request.end(data, options.encoding);        
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
