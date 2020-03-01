/**
 * Web Request Signature Implementation for Web Browsers
 *
 * Original code base from: Daniel Joos
 */

;(function (root, factory) {
    root.reqSignWeb = factory();
}(this, function () {
    'use strict';

    var defaultConfig = {
        defaultContentType: 'application/json',
        defaultAcceptType: 'application/json',
        payloadSerializerFactory: JsonPayloadSerializer,
        uriParserFactory: SimpleUriParser
    };

    /**
     * Create a new signer object with the given configuration.
     * Configuration must specify the credentials used for the signing operation.
     * It must contain the following properties:
     * `signKey`: The signing key.
     * `requestId`: The identifier of this request.
     * @param {object} config The configuration object.
     * @constructor
     */
    var ReqSigner = function (config) {
        this.config = extend({}, defaultConfig, config);
        assertRequired(this.config.signKey, 'ReqSigner requires a SignKey');
        assertRequired(this.config.signKey.length >= 64, 'SignKey must be 32 bytes long');
        assertRequired(this.config.requestId, 'ReqSigner requires a RequestId');
        this.payloadSerializer = this.config.payloadSerializer ||
            this.config.payloadSerializerFactory();
        this.uriParser = this.config.uriParserFactory();
    };

    ReqSigner.prototype.update = async function (requestId) {
        // Update the next request id
        this.config.requestId = requestId;
        //  Pass the shared key hex string through SHA256
        this.config.signKey = await SHA256(this.config.signKey);
    };

    /**
     * Create signature headers for the given request.
     * Request must be in the format, known from the `$http` service of Angular:
     * ```
     * request = {
     *      headers: { ... },
     *      method: 'GET',
     *      url: 'http://...',
     *      params: { ... },
     *      data: ...           // alternative: body
     * };
     * ```
     * The resulting object contains the signature headers. For example, it can be merged into an
     * existing `$http` config when dealing with Angular JS.
     * @param {object} request The request to create the signature for.
     * @returns Signed request.
     */
    ReqSigner.prototype.sign = async function (request) {
        if (typeof request.headers !== "undefined") {
            request.headers = {};
        }
        if (typeof request.data !== "undefined") {
            var ct_iv = await encrypt(this, request.data);
            request.data = ct_iv[0];
            request.headers['X-IV'] = ct_iv[1];
            request.headers['X-Payload-Encrypted'] = "1";
            request.headers['Content-Type'] = 'text/plain';
        }
        else {
            request.headers['X-Payload-Encrypted'] = "0";
        }

        var workingSet = {
            request: extend({}, request),
            uri: this.uriParser(request.url)
        };
        prepare(this, workingSet);
        await buildCanonicalRequest(this, workingSet);    // Step1: build the canonical request
        await buildStringToSign(this, workingSet);        // Step2: build the string to sign
        await calculateSignature(this, workingSet);       // Step3: calculate the signature hash
        buildSignatureHeader(this, workingSet);     // Step4: build the authorization header

        request.headers['Accept'] = workingSet.request.headers['accept'];
        request.headers['Authorization'] = workingSet.authorization;
        request.headers['X-Request-Id'] = this.config.requestId;
        return request;
    };

    // Some preparations
    function prepare(self, ws) {
        var headers = {
            'host': ws.uri.host,
            'content-type': self.config.defaultContentType,
            'accept': self.config.defaultAcceptType,
            'x-request-id': self.config.requestId
        };
        // Remove accept/content-type headers if no default was configured.
        if (!self.config.defaultAcceptType) {
            delete headers['accept'];
        }
        if (!self.config.defaultContentType) {
            delete headers['content-type'];
        }
        // Payload or not?
        ws.request.method = ws.request.method.toUpperCase();
        if (ws.request.body) {
            ws.payload = ws.request.body;
        } else if (ws.request.data && self.payloadSerializer) {
            ws.payload = ws.request.data;
        } else {
            delete headers['content-type'];
        }
        // Headers
        ws.request.headers = extend(
            headers,
            Object.keys(ws.request.headers || {}).reduce(function (normalized, key) {
                normalized[key.toLowerCase()] = ws.request.headers[key];
                return normalized;
            }, {})
        );
        ws.sortedHeaderKeys = Object.keys(ws.request.headers).sort();
        // Remove content-type parameters as some browser might change them on send
        if (ws.request.headers['content-type']) {
            ws.request.headers['content-type'] = ws.request.headers['content-type'].split(';')[0];
        }
        // Merge params to query params
        if (typeof(ws.request.params) === 'object') {
            extend(ws.uri.queryParams, ws.request.params);
        }
    }

    async function encrypt(self, plaintext) {
        return await encryptMessage(plaintext, self.config.signKey);
    }

    // Convert the request to a canonical format.
    async function buildCanonicalRequest(self, ws) {
        ws.signedHeaders = ws.sortedHeaderKeys.map(function (key) {
            return key.toLowerCase();
        }).join(';');
        ws.canonicalRequest = String(ws.request.method).toUpperCase() + '\n' +
                // Canonical URI:
            ws.uri.path.split('/').map(function(seg) {
                return uriEncode(seg);
            }).join('/') + '\n' +
                // Canonical Query String:
            flatten(Object.keys(ws.uri.queryParams).sort().map(function (key) {
                // how about array params?
                return encodeURIComponent(key) + '=' + encodeURIComponent(ws.uri.queryParams[key]);
                // this breaks
                //return ws.uri.queryParams[key].sort().map(function(val) {
                //    return encodeURIComponent(key) + '=' + encodeURIComponent(val);
                //})
            })).join('&') + '\n' +
                // Canonical Headers:
            ws.sortedHeaderKeys.map(function (key) {
                return key.toLocaleLowerCase() + ':' + ws.request.headers[key];
            }).join('\n') + '\n\n' +
                // Signed Headers:
            ws.signedHeaders + '\n' +
                // Hashed Payload
            await SHA256((ws.payload) ? ws.payload : '');
            if (window.verbose_log) {
                console.log('canonical request:\n' + ws.canonicalRequest);
            }
    }

    // Construct the string that will be signed.
    async function buildStringToSign(self, ws) {
        ws.stringToSign = 'AWS4-HMAC-SHA256' + '\n' +
            await SHA256(ws.canonicalRequest);
    }

    // Calculate the signature
    async function calculateSignature(self, ws) {
        ws.signature = await sign_hmac(ws.stringToSign, self.config.signKey);
    }

    // Build the signature HTTP header using the data in the working set.
    function buildSignatureHeader(self, ws) {
        ws.authorization = 'AWS4-HMAC-SHA256 ' +
            'SignedHeaders=' + ws.signedHeaders + ', ' +
            'Signature=' + ws.signature;
    }

    /**
     * Payload serializer factory implementation that converts the data to a JSON string.
     */
    function JsonPayloadSerializer() {
        return function(data) {
            return JSON.stringify(data);
        };
    }

    /**
     * Simple URI parser factory.
     * Uses an `a` document element for parsing given URIs.
     * Therefore it most likely will only work in a web browser.
     */
    function SimpleUriParser() {
        var parser = document ? document.createElement('a') : {};

        /**
         * Parse the given URI.
         * @param {string} uri The URI to parse.
         * @returns JavaScript object with the parse results:
         * `protocol`: The URI protocol part.
         * `host`: Host part of the URI.
         * `path`: Path part of the URI, always starting with a `/`
         * `queryParams`: Query parameters as JavaScript object.
         */
        return function (uri) {
            parser.href = uri;
            return {
                protocol: parser.protocol,
                host: parser.host.replace(/^(.*):((80)|(443))$/, '$1'),
                path: ((parser.pathname.charAt(0) !== '/') ? '/' : '') +
                    decodeURI(parser.pathname),
                queryParams: extractQueryParams(parser.search)
            };
        };

        function extractQueryParams(search) {
            return /^\??(.*)$/.exec(search)[1].split('&').reduce(function (result, arg) {
                arg = /^(.+)=(.*)$/.exec(arg);
                if (arg) {
                    var paramKey = decodeURI(arg[1]);
                    result[paramKey] = (
                        (typeof result[paramKey] != 'undefined' && result[paramKey] instanceof Array)
                            ? result[paramKey]
                            : []
                    ).concat(decodeURI(arg[2]));
                }
                return result;
            }, {});
        }
    }

    /**
     * URI encode according to S3 requirements.
     * See: http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
     * See: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
     */
    function uriEncode(input) {
        return encodeURIComponent(input).replace(/[!'()*]/g, function(c) {
            return '%' + c.charCodeAt(0).toString(16).toUpperCase();
        });
    }

    // Simple version of the `extend` function, known from Angular and Backbone.
    // It merges the second (and all succeeding) argument(s) into the object, given as first
    // argument. This is done recursively for all child objects, as well.
    function extend(dest) {
        var objs = [].slice.call(arguments, 1);
        objs.forEach(function (obj) {
            if (!obj || typeof(obj) !== 'object') {
                return;
            }
            Object.keys(obj).forEach(function (key) {
                var src = obj[key];
                if (typeof(src) === 'undefined') {
                    return;
                }
                if (src !== null && typeof(src) === 'object') {
                    dest[key] = (Array.isArray(src) ? [] : {});
                    extend(dest[key], src);
                } else {
                    dest[key] = src;
                }
            });
        });
        return dest;
    }

    // Short function that uses some JavaScript array methods to flatten an n-dimensional array.
    function flatten(arr) {
        return arr.reduce(function (flat, toFlatten) {
            return flat.concat(Array.isArray(toFlatten) ? flatten(toFlatten) : toFlatten);
        }, []);
    }

    // Throw an error if the given object is undefined.
    function assertRequired(obj, msg) {
        if (typeof(obj) === 'undefined' || !obj) {
            throw new Error(msg);
        }
    }

    return {
        ReqSigner: ReqSigner
    };
}));
