/*global module */

module.exports = (function(){
    "use strict";
    
    function PandaError(code, error, message, data) {
        if (Error.captureStackTrace)
            Error.captureStackTrace(this, this.constructor);

        this.name = 'PandaError';

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

    
    var ERROR_TYPE = {
        1: 'type error',
        2: 'oauth error',
        3: 'params error',
        4: 'timeout error'
    };

    var E = {
        TYPE_ERROR: ERROR_TYPE[1],
        OAUTH_ERROR: ERROR_TYPE[2],
        PARAMS_ERROR: ERROR_TYPE[3],
        TIMEOUT_ERROR: ERROR_TYPE[4]
    };

    
    var C = {
        TYPE_ERROR: 1,
        OAUTH_ERROR: 2,
        PARAMS_ERROR: 3,
        TIMEOUT_ERROR: 4
    };
    
    var ERROR = {
        TYPE: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'invalid type'
        },
        OPTIONS: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'missing or invalid options object'
        },
        SHOP: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'shop must be a hostname string'
        },
        CALLBACK: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'callback must be a function'
        },
        LOGGER: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'logger must be a function'
        },
        OAUTH: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'oauth must be an object'
        },
        STREAM: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'missing or invalid stream class'
        },
        PARAMS: {
            code: C.TYPE_ERROR,
            error: E.TYPE_ERROR,
            message: 'missing parameters object'
        },
        OAUTH_SCOPE: {
            code: C.OAUTH_ERROR,
            error: E.OAUTH_ERROR,
            message: 'missing or invalid oauth scope'
        },
        OAUTH_API_KEY: {
            code: C.OAUTH_ERROR,
            error: E.OAUTH_ERROR,
            message: 'missing or invalid oauth api_key'
        },
        OAUTH_PRIVATE_KEY: {
            code: C.OAUTH_ERROR,
            error: E.OAUTH_ERROR,
            message: 'missing or invalid oauth private_key'
        },
        OAUTH_SIGNATURE: {
            code: C.OAUTH_ERROR,
            error: E.OAUTH_ERROR,
            message: 'oauth signature mismatch'
        },
        OAUTH_SHARED_SECRET: {
            code: C.OAUTH_ERROR,
            error: E.OAUTH_ERROR,
            message: 'missing or invalid oauth shared_secret'
        },
        SIGNATURE_PARAM: {
            code: C.PARAMS_ERROR,
            error: E.PARAMS_ERROR,
            message: 'missing or invalid signature'
        },
        CODE_PARAM: {
            code: C.PARMAS_ERROR,
            error: E.PARAMS_ERROR,
            message: 'missing or invalid code'
        },
        TIMEOUT: {
            code: C.TIMEOUT_ERROR,
            error: E.TIMEOUT_ERROR,
            message: 'operation timed out'
        }
    };

    PandaError.ERROR = ERROR;

    return PandaError;
}());
