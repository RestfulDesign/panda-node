/*global module */

module.exports = (function(){
    "use strict";
    
    function PandaError(code, error, message, data) {
        if (Error.captureStackTrace)
            Error.captureStackTrace(this, this.constructor);

        this.name = 'PandaError';

        if (isNaN(code)) {
            data = error;
            error = code;
        }

        if (typeof error === 'object') {
            this.code = error.code;
            if(!this.code) this.code = 0;
            this.error = error.error;
            this.message = error.message;
            this.data = error.data;
            if(!this.data) this.data = data;
        } else {
            this.code = code;
            this.error = error;
            this.message = message;
            this.data = data;
        }
    }

    PandaError.prototype = Object.create(Error.prototype);
    PandaError.prototype.constructor = PandaError;

    function HttpError(code, error, message, request){
        this.name = 'HttpError';
        this.code = code;
        this.error = error;
        this.message = message;
        this.request = request;
    }

    HttpError.prototype = Object.create(Error.prototype);
    HttpError.prototype.constructor = HttpError;
    
    var ERROR_TYPE = {
        0: 'error',
        1: 'type error',
        2: 'oauth error',
        3: 'params error',
        4: 'timeout error'
    };

    
    var ERROR = {
        TYPE: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'invalid type'
        },
        OPTIONS: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'missing or invalid options object'
        },
        SHOP: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'shop must be a hostname string'
        },
        CALLBACK: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'callback must be a function'
        },
        LOGGER: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'logger must be a function'
        },
        OAUTH: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'oauth must be an object'
        },
        STREAM: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'missing or invalid stream class'
        },
        PARAMS: {
            code: 1,
            error: ERROR_TYPE[1],
            message: 'missing parameters object'
        },
        OAUTH_SCOPE: {
            code: 2,
            error: ERROR_TYPE[2],
            message: 'missing or invalid oauth scope'
        },
        OAUTH_API_KEY: {
            code: 2,
            error: ERROR_TYPE[2],
            message: 'missing or invalid oauth api_key'
        },
        OAUTH_PRIVATE_KEY: {
            code: 2,
            error: ERROR_TYPE[2],
            message: 'missing or invalid oauth private_key'
        },
        OAUTH_SIGNATURE: {
            code: 2,
            error: ERROR_TYPE[2],
            message: 'oauth signature mismatch'
        },
        OAUTH_SHARED_SECRET: {
            code: 2,
            error: ERROR_TYPE[2],
            message: 'missing or invalid oauth shared_secret'
        },
        SIGNATURE_PARAM: {
            code: 3,
            error: ERROR_TYPE[3],
            message: 'missing or invalid signature'
        },
        CODE_PARAM: {
            code: 3,
            error: ERROR_TYPE[3],
            message: 'missing or invalid code'
        },
        TIMEOUT: {
            code: 4,
            error: ERROR_TYPE[4],
            message: 'operation timed out'
        },
        HTTP_REQUEST: {
            code: 5,
            error: ERROR_TYPE[5],
            message: 'request failed'
        }
    };

    PandaError.ERROR = ERROR;

    return {
        PandaError: PandaError,
        HttpError: HttpError
    };
}());
