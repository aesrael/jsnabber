// JSNabber Instrumentation & API Stubbing
// Injected before user code executes to wrap dangerous APIs and provide stubs.

(function () {
  // --- Core Instrumentation Hooks ---

  // 1. Wrap Function constructor
  const nativeFunction = globalThis.Function;
  globalThis.Function = function (...args) {
    const code = args[args.length - 1];
    __jsnabber_log(
      "FunctionConstructor",
      typeof code === "string" ? code : String(code),
    );
    return nativeFunction.apply(this, args);
  };
  globalThis.Function.prototype = nativeFunction.prototype;

  // 2. Wrap eval
  const nativeEval = globalThis.eval;
  if (nativeEval) {
    globalThis.eval = function (code) {
      __jsnabber_log("eval", code);
      return nativeEval(code);
    };
  }

  // 3. Wrap atob (base64 decode)
  const nativeAtob = globalThis.atob || globalThis.__js_atob;
  if (nativeAtob) {
    globalThis.atob = function (str) {
      const result = nativeAtob(str);
      const strVal = String(str);
      const resVal = String(result);
      __jsnabber_log(
        "atob",
        `atob(${strVal.substring(0, 50)}...) -> ${resVal.substring(0, 50)}...`,
      );
      return result;
    };
  }

  // 4. Wrap btoa (base64 encode)
  const nativeBtoa = globalThis.btoa;
  if (nativeBtoa) {
    // Wrap existing native btoa
    globalThis.btoa = function (str) {
      const strVal = String(str);
      __jsnabber_log("btoa", `btoa(${strVal.substring(0, 50)}...)`);
      return nativeBtoa(str);
    };
  } else {
    // Polyfill if missing
    globalThis.btoa = function (str) {
      const strVal = String(str);
      __jsnabber_log("btoa", `btoa(${strVal.substring(0, 50)}...)`);
      // Simple base64 encode (not perfect but good enough for analysis)
      return Buffer ? Buffer.from(str).toString("base64") : str;
    };
  }

  // 5. Wrap String.fromCharCode
  const nativeFromCharCode = String.fromCharCode;
  if (nativeFromCharCode) {
    String.fromCharCode = function (...args) {
      const result = nativeFromCharCode.apply(String, args);
      const resVal = String(result);
      __jsnabber_log(
        "fromCharCode",
        `fromCharCode(${args.slice(0, 10).join(",")}) -> ${resVal.substring(0, 50)}...`,
      );
      return result;
    };
  }

  // 6. Wrap Math.random
  const nativeRandom = Math.random;
  Math.random = function () {
    const result = nativeRandom();
    __jsnabber_log("random", `Math.random() -> ${result}`);
    return result;
  };

  // 7. Wrap Timers
  const nativeSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = function (fn, delay, ...args) {
    __jsnabber_log("timer", `setTimeout(..., ${delay})`);
    if (nativeSetTimeout) return nativeSetTimeout(fn, delay, ...args);
    return 0;
  };

  const nativeSetInterval = globalThis.setInterval;
  globalThis.setInterval = function (fn, delay, ...args) {
    __jsnabber_log("timer", `setInterval(..., ${delay})`);
    if (nativeSetInterval) return nativeSetInterval(fn, delay, ...args);
    return 0;
  };

  // 8. Polyfill Array.from (some malware uses this)
  if (!Array.from) {
    Array.from = function (arrayLike, mapFn, thisArg) {
      var arr = [];
      for (var i = 0; i < arrayLike.length; i++) {
        arr.push(mapFn ? mapFn.call(thisArg, arrayLike[i], i) : arrayLike[i]);
      }
      return arr;
    };
  }

  // 9. Stub obfuscated global functions (some malware compilers use these)
  if (!globalThis.$Array_from) {
    globalThis.$Array_from = Array.from;
  }
  if (!globalThis.$Math_min) {
    globalThis.$Math_min = Math.min;
  }
  if (!globalThis.$Math_max) {
    globalThis.$Math_max = Math.max;
  }
  if (!globalThis.$Math_floor) {
    globalThis.$Math_floor = Math.floor;
  }
  if (!globalThis.$Math_ceil) {
    globalThis.$Math_ceil = Math.ceil;
  }
  if (!globalThis.$Math_round) {
    globalThis.$Math_round = Math.round;
  }
  if (!globalThis.$Object_keys) {
    globalThis.$Object_keys = Object.keys;
  }
  if (!globalThis.$Object_values) {
    globalThis.$Object_values = Object.values;
  }
  if (!globalThis.$Object_entries) {
    globalThis.$Object_entries = Object.entries;
  }
  if (!globalThis.$JSON_parse) {
    globalThis.$JSON_parse = JSON.parse;
  }
  if (!globalThis.$JSON_stringify) {
    globalThis.$JSON_stringify = JSON.stringify;
  }

  // --- Storage Wrapping ---
  const wrapStorage = (name, storage) => {
    if (!storage) return;
    const originalGet = storage.getItem;
    storage.getItem = function (key) {
      __jsnabber_log("storage", `${name}.getItem(${key})`);
      return originalGet.call(storage, key);
    };
    const originalSet = storage.setItem;
    storage.setItem = function (key, value) {
      __jsnabber_log("storage", `${name}.setItem(${key}, ${value})`);
      return originalSet.call(storage, key, value);
    };
    const originalRemove = storage.removeItem;
    storage.removeItem = function (key) {
      __jsnabber_log("storage", `${name}.removeItem(${key})`);
      return originalRemove.call(storage, key);
    };
  };

  wrapStorage("localStorage", globalThis.localStorage);
  wrapStorage("sessionStorage", globalThis.sessionStorage);

  // --- Console Stub ---

  if (!globalThis.console) {
    globalThis.console = {
      log: function (...args) {
        __jsnabber_log("system", `console.log(${args.length} args)`);
      },
      warn: function (...args) {
        __jsnabber_log("system", `console.warn(${args.length} args)`);
      },
      error: function (...args) {
        __jsnabber_log("system", `console.error(${args.length} args)`);
      },
      info: function (...args) {
        __jsnabber_log("system", `console.info(${args.length} args)`);
      },
      debug: function (...args) {
        __jsnabber_log("system", `console.debug(${args.length} args)`);
      },
    };
  }

  // --- Network API Stubs

  // Fetch API
  if (!globalThis.fetch) {
    globalThis.fetch = function (url, options) {
      __jsnabber_log(
        "network",
        `fetch(${url}, ${JSON.stringify(options || {})})`,
      );
      return Promise.resolve({
        ok: false,
        status: 404,
        statusText: "Not Found",
        headers: new Map(),
        text: () => Promise.resolve("Sandbox: Network blocked"),
        json: () => Promise.resolve({}),
        blob: () => Promise.resolve(new Blob()),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
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

  // Navigator stub
  if (!globalThis.navigator) {
    const nav = {
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      platform: "MacIntel",
      language: "en-US",
      languages: ["en-US", "en"],
      onLine: true,
      cookieEnabled: true,
      doNotTrack: "1",
    };
    globalThis.navigator = new Proxy(nav, {
      get(target, prop) {
        __jsnabber_log("evasion", `navigator.${String(prop)} access`);
        return target[prop];
      },
    });
  }

  // Document stub
  if (!globalThis.document) {
    const createElementStub = (tag) => ({
      tagName: tag.toUpperCase(),
      innerHTML: "",
      textContent: "",
      src: "",
      href: "",
      style: {},
      setAttribute: function (name, value) {
        __jsnabber_log("dom", `element.setAttribute(${name}, ${value})`);
        this[name] = value;
      },
      getAttribute: function (name) {
        return this[name];
      },
      appendChild: function (child) {
        __jsnabber_log("dom", `element.appendChild(${child.tagName})`);
        return child;
      },
      addEventListener: function (event, handler) {
        __jsnabber_log("dom", `element.addEventListener(${event}, ...)`);
      },
    });

    globalThis.document = {
      createElement: function (tag) {
        __jsnabber_log("dom", `document.createElement(${tag})`);
        const el = createElementStub(tag);
        // Special tracking for script/iframe
        if (tag.toLowerCase() === "script" || tag.toLowerCase() === "iframe") {
          __jsnabber_log("dom", `Suspicious element creation: ${tag}`);
        }
        return el;
      },
      getElementById: function (id) {
        __jsnabber_log("dom", `document.getElementById(${id})`);
        return createElementStub("div");
      },
      querySelector: function (selector) {
        __jsnabber_log("dom", `document.querySelector(${selector})`);
        return createElementStub("div");
      },
      querySelectorAll: function (selector) {
        __jsnabber_log("dom", `document.querySelectorAll(${selector})`);
        return [];
      },
      addEventListener: function (event, handler) {
        __jsnabber_log("dom", `document.addEventListener(${event}, ...)`);
      },
      cookie: "",
      referrer: "",
      location: globalThis.location, // Share the same location object
      head: createElementStub("head"),
      body: createElementStub("body"),
    };
  }

  // --- Node.js API Stubs

  // require() stub for Node.js malware
  if (!globalThis.require) {
    globalThis.require = function (module) {
      __jsnabber_log("system", `require('${module}')`);

      // Return fake modules
      const fakeModules = {
        fs: { readFileSync: () => "", writeFileSync: () => {} },
        http: { request: () => ({}), createServer: () => ({}) },
        https: { request: () => ({}), get: () => ({}) },
        child_process: { exec: () => {}, spawn: () => ({}) },
        crypto: {
          createHash: () => ({ update: () => ({}), digest: () => "" }),
        },
        os: { platform: () => "linux", hostname: () => "sandbox" },
        path: {
          join: (...args) => args.join("/"),
          resolve: (...args) => "/" + args.join("/"),
        },
      };

      return fakeModules[module] || {};
    };
  }

  // process stub for Node.js malware
  if (!globalThis.process) {
    globalThis.process = {
      version: "v16.0.0",
      platform: "linux",
      arch: "x64",
      env: {},
      argv: ["node", "script.js"],
      cwd: () => "/sandbox",
      exit: (code) => {
        __jsnabber_log("system", `process.exit(${code})`);
      },
    };
  }

  // module stub for Node.js malware
  if (!globalThis.module) {
    globalThis.module = {
      exports: {},
      require: globalThis.require,
      id: "sandbox",
      filename: "/sandbox/script.js",
      loaded: false,
      parent: null,
      children: [],
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
        __jsnabber_log("system", `Buffer.from(..., ${encoding})`);
        return { toString: (enc) => String(data) };
      },
      alloc: (size) => ({ toString: () => "" }),
    };
  }

  // --- Evasion / Reflect wrapping ---
  if (globalThis.Reflect) {
    const originalApply = Reflect.apply;
    Reflect.apply = function (target, thisArg, args) {
      __jsnabber_log(
        "evasion",
        `Reflect.apply(${target.name || "anonymous"}, ...)`,
      );
      return originalApply(target, thisArg, args);
    };

    const originalConstruct = Reflect.construct;
    Reflect.construct = function (target, args, newTarget) {
      __jsnabber_log(
        "evasion",
        `Reflect.construct(${target.name || "anonymous"}, ...)`,
      );
      return originalConstruct(target, args, newTarget);
    };
  }

  // --- Proxy-Based Catch-All for Undefined Globals

  // Recursive stub generator
  const createRecursiveStub = (name) => {
    const stub = new Proxy(function () {}, {
      get(target, prop) {
        if (prop === "toString") return () => `[Stub ${name}]`;
        if (prop === Symbol.toPrimitive) return () => `[Stub ${name}]`;
        return createRecursiveStub(`${name}.${String(prop)}`);
      },
      apply(target, thisArg, args) {
        __jsnabber_log(
          "evasion",
          `Called undefined global: ${name}(${args.length} args)`,
        );
        return createRecursiveStub(`${name}()`);
      },
      construct(target, args) {
        __jsnabber_log(
          "evasion",
          `Constructed undefined global: new ${name}(${args.length} args)`,
        );
        return createRecursiveStub(`new ${name}()`);
      },
    });
    return stub;
  };

  // Wrap globalThis in a Proxy to catch any undefined property access
  const globalProxy = new Proxy(globalThis, {
    get(target, prop, receiver) {
      // Avoid trapping symbols or known props
      if (typeof prop === "symbol") return Reflect.get(target, prop, receiver);
      if (prop in target) return Reflect.get(target, prop, receiver);


      // Whitelist of common library patterns that are NOT evasion
      const benignPatterns = ["onLoad", "onReady", "onInit", "onError", "onComplete", "onSuccess", "onChange", "onClick", "onSubmit", "onFocus", "onBlur", "onResize", "onScroll", "DOMContentLoaded", "addEventListener", "removeEventListener", "jQuery", "$", "_", "React", "Vue", "Angular", "bootstrap", "main", "init", "start", "run", "execute", "setup", "launch", "begin", "entry"];
      const propStr = String(prop);
      const isBenign = benignPatterns.includes(propStr) || propStr.startsWith("on");

      // Only log as evasion if it's NOT a benign pattern
      if (!isBenign) {
        __jsnabber_log("evasion", `Accessed undefined global: ${propStr}`);
      }

      // Return recursive stub
      return createRecursiveStub(String(prop));
    },
    has(target, prop) {
      // Always say we have it to prevent ReferenceError
      return true;
    },
  });

  globalThis.__magic_global_proxy = globalProxy;

  // Create a specific Fallback Proxy for the prototype chain
  // This avoids reference cycles (globalThis -> Proxy(globalThis) -> globalThis)
  const fallbackProxy = new Proxy(
    {},
    {
      get(target, prop) {
        // Check symbols/internals
        if (typeof prop === "symbol") return undefined;
        __jsnabber_log(
          "evasion",
          `Accessed undefined global (via prototype): ${String(prop)}`,
        );
        return createRecursiveStub(String(prop));
      },
      has(target, prop) {
        return true; // Claim we have everything!
      },
    },
  );

  try {
    // specific aliases
    if (globalThis.window) {
      Object.setPrototypeOf(globalThis.window, fallbackProxy);
    }

    // globalThis itself
    Object.setPrototypeOf(globalThis, fallbackProxy);
  } catch (e) {
    __jsnabber_log("error", "Failed to set prototypes: " + e.message);
  }

  globalThis.self = globalProxy;
  globalThis.top = globalProxy;
  globalThis.parent = globalProxy; // These might not stick if readonly, but prototype will help.

  // Note: We can't actually replace globalThis with the proxy in QuickJS,
  // but we've stubbed the most common APIs above to prevent failures.
})();
