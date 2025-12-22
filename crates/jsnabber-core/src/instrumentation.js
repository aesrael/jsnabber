// JSNabber Instrumentation & API Stubbing
// Injected before user code executes to wrap dangerous APIs and provide stubs.

(function() {
    'use strict';

    // --- Core Instrumentation Hooks ---

    // 1. Wrap Function constructor
    const nativeFunction = globalThis.Function;
    globalThis.Function = function(...args) {
        const code = args[args.length - 1];
        __jsnabber_log("FunctionConstructor", typeof code === 'string' ? code : String(code));
        return nativeFunction.apply(this, args);
    };
    globalThis.Function.prototype = nativeFunction.prototype;

    // 2. Wrap eval
    const nativeEval = globalThis.eval;
    if (nativeEval) {
        globalThis.eval = function(code) {
            __jsnabber_log("eval", code);
            return nativeEval(code);
        };
    }

    // 3. Wrap atob (base64 decode)
    const nativeAtob = globalThis.atob || globalThis.__js_atob;
    if (nativeAtob) {
        globalThis.atob = function(str) {
            const result = nativeAtob(str);
            __jsnabber_log("atob", `atob(${str.substring(0, 50)}...) -> ${result.substring(0, 50)}...`);
            return result;
        };
    }

    // 4. Wrap btoa (base64 encode)
    if (!globalThis.btoa) {
        globalThis.btoa = function(str) {
            __jsnabber_log("btoa", `btoa(${str.substring(0, 50)}...)`);
            // Simple base64 encode (not perfect but good enough for analysis)
            return Buffer ? Buffer.from(str).toString('base64') : str;
        };
    }

    // 5. Wrap String.fromCharCode
    const nativeFromCharCode = String.fromCharCode;
    if (nativeFromCharCode) {
        String.fromCharCode = function(...args) {
            const result = nativeFromCharCode.apply(String, args);
            __jsnabber_log("fromCharCode", `fromCharCode(${args.slice(0, 10).join(',')}) -> ${result.substring(0, 50)}...`);
            return result;
        };
    }

    // 6. Wrap Math.random
    const nativeRandom = Math.random;
    Math.random = function() {
        const result = nativeRandom();
        __jsnabber_log("random", `Math.random() -> ${result}`);
        return result;
    };

    // 7. Wrap Timers
    const nativeSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = function(fn, delay, ...args) {
        __jsnabber_log("timer", `setTimeout(..., ${delay})`);
        if (nativeSetTimeout) return nativeSetTimeout(fn, delay, ...args);
        return 0;
    };

    const nativeSetInterval = globalThis.setInterval;
    globalThis.setInterval = function(fn, delay, ...args) {
        __jsnabber_log("timer", `setInterval(..., ${delay})`);
        if (nativeSetInterval) return nativeSetInterval(fn, delay, ...args);
        return 0;
    };

    
    // --- Network API Stubs
    

    // Fetch API
    if (!globalThis.fetch) {
        globalThis.fetch = function(url, options) {
            __jsnabber_log("network", `fetch(${url}, ${JSON.stringify(options || {})})`);
            return Promise.resolve({
                ok: false,
                status: 404,
                statusText: 'Not Found',
                headers: new Map(),
                text: () => Promise.resolve("Sandbox: Network blocked"),
                json: () => Promise.resolve({}),
                blob: () => Promise.resolve(new Blob()),
                arrayBuffer: () => Promise.resolve(new ArrayBuffer(0))
            });
        };
    }

    // XMLHttpRequest
    if (!globalThis.XMLHttpRequest) {
        globalThis.XMLHttpRequest = class {
            constructor() {
                __jsnabber_log("network", "new XMLHttpRequest()");
                this.readyState = 0;
                this.status = 0;
                this.responseText = "";
            }
            open(method, url) {
                __jsnabber_log("network", `XHR.open(${method}, ${url})`);
            }
            send(data) {
                __jsnabber_log("network", `XHR.send(${data})`);
            }
            setRequestHeader(name, value) {}
        };
    }

    // WebSocket
    if (!globalThis.WebSocket) {
        globalThis.WebSocket = class {
            constructor(url) {
                __jsnabber_log("network", `new WebSocket(${url})`);
                this.readyState = 0;
            }
            send(data) {
                __jsnabber_log("network", `WebSocket.send(${data})`);
            }
            close() {}
        };
    }

    // --- Browser DOM Stubs ---
    // Note: window and location are injected from Rust before this script runs
    
    // Document stub
    if (!globalThis.document) {
        const createElementStub = (tag) => ({
            tagName: tag.toUpperCase(),
            innerHTML: '',
            textContent: '',
            src: '',
            href: '',
            style: {},
            setAttribute: function(name, value) {
                __jsnabber_log("dom", `element.setAttribute(${name}, ${value})`);
                this[name] = value;
            },
            getAttribute: function(name) { return this[name]; },
            appendChild: function(child) {
                __jsnabber_log("dom", `element.appendChild(${child.tagName})`);
                return child;
            },
            addEventListener: function(event, handler) {
                __jsnabber_log("dom", `element.addEventListener(${event}, ...)`);
            }
        });

        globalThis.document = {
            createElement: function(tag) {
                __jsnabber_log("dom", `document.createElement(${tag})`);
                return createElementStub(tag);
            },
            getElementById: function(id) {
                __jsnabber_log("dom", `document.getElementById(${id})`);
                return createElementStub('div');
            },
            querySelector: function(selector) {
                __jsnabber_log("dom", `document.querySelector(${selector})`);
                return createElementStub('div');
            },
            querySelectorAll: function(selector) {
                __jsnabber_log("dom", `document.querySelectorAll(${selector})`);
                return [];
            },
            addEventListener: function(event, handler) {
                __jsnabber_log("dom", `document.addEventListener(${event}, ...)`);
            },
            cookie: '',
            referrer: '',
            location: globalThis.location,  // Share the same location object
            head: createElementStub('head'),
            body: createElementStub('body')
        };
    }

    
    // --- Node.js API Stubs
    

    // require() stub for Node.js malware
    if (!globalThis.require) {
        globalThis.require = function(module) {
            __jsnabber_log("require", `require('${module}')`);
            
            // Return fake modules
            const fakeModules = {
                'fs': { readFileSync: () => '', writeFileSync: () => {} },
                'http': { request: () => ({}), createServer: () => ({}) },
                'https': { request: () => ({}), get: () => ({}) },
                'child_process': { exec: () => {}, spawn: () => ({}) },
                'crypto': { createHash: () => ({ update: () => ({}), digest: () => '' }) },
                'os': { platform: () => 'linux', hostname: () => 'sandbox' },
                'path': { join: (...args) => args.join('/'), resolve: (...args) => '/' + args.join('/') }
            };
            
            return fakeModules[module] || {};
        };
    }

    // process stub for Node.js malware
    if (!globalThis.process) {
        globalThis.process = {
            version: 'v16.0.0',
            platform: 'linux',
            arch: 'x64',
            env: {},
            argv: ['node', 'script.js'],
            cwd: () => '/sandbox',
            exit: (code) => {
                __jsnabber_log("process", `process.exit(${code})`);
            }
        };
    }

    // module stub for Node.js malware
    if (!globalThis.module) {
        globalThis.module = {
            exports: {},
            require: globalThis.require,
            id: 'sandbox',
            filename: '/sandbox/script.js',
            loaded: false,
            parent: null,
            children: []
        };
    }

    // exports stub
    if (!globalThis.exports) {
        globalThis.exports = globalThis.module ? globalThis.module.exports : {};
    }

    // Buffer stub
    if (!globalThis.Buffer) {
        globalThis.Buffer = {
            from: (data, encoding) => {
                __jsnabber_log("buffer", `Buffer.from(..., ${encoding})`);
                return { toString: (enc) => String(data) };
            },
            alloc: (size) => ({ toString: () => '' })
        };
    }

    
    // --- Proxy-Based Catch-All for Undefined Globals
    

    // Wrap globalThis in a Proxy to catch any undefined property access
    const globalProxy = new Proxy(globalThis, {
        get(target, prop, receiver) {
            // If property exists, return it
            if (prop in target) {
                return Reflect.get(target, prop, receiver);
            }
            
            // Log access to undefined global
            __jsnabber_log("undefined_global", `Accessed undefined global: ${String(prop)}`);
            
            // Return a stub function/object to prevent errors
            return function(...args) {
                __jsnabber_log("undefined_call", `Called undefined global: ${String(prop)}(${args.length} args)`);
                return undefined;
            };
        }
    });

    // Note: We can't actually replace globalThis with the proxy in QuickJS,
    // but we've stubbed the most common APIs above to prevent failures.
})();
