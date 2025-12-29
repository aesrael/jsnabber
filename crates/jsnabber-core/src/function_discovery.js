// JSNabber Function Discovery & Auto-Execution
// Injected after user code to trigger dormant malicious functions

(function () {
  const executedFunctions = new Set();
  const maxDepth = 3; // Prevent infinite recursion
  const maxExecutions = 50; // Safety limit
  let executionCount = 0;

  // Helper to generate dummy arguments for function calls
  function generateDummyArgs(func) {
    const argCount = func.length; // Number of expected parameters
    const dummyArgs = [];

    for (let i = 0; i < argCount; i++) {
      dummyArgs.push(undefined); // Or could use: {}, [], "", 0, etc.
    }

    return dummyArgs;
  }

  // Recursively discover and call functions
  function discoverAndExecute(obj, path = "", depth = 0) {
    if (depth > maxDepth || executionCount >= maxExecutions) return;
    if (!obj || typeof obj !== "object") return;

    try {
      const keys = Object.keys(obj);

      for (const key of keys) {
        if (executionCount >= maxExecutions) break;

        try {
          const value = obj[key];
          const fullPath = path ? `${path}.${key}` : key;

          // Skip already executed
          if (executedFunctions.has(fullPath)) continue;

          // If it's a function, try to call it
          if (typeof value === "function") {
            // Skip native/built-in functions
            const funcStr = value.toString();
            if (funcStr.includes("[native code]")) continue;

            // Skip our own instrumentation
            if (key.startsWith("__jsnabber")) continue;

            executedFunctions.add(fullPath);
            executionCount++;

            __jsnabber_log(
              "function_discovery",
              `Calling discovered function: ${fullPath}`,
            );

            try {
              const args = generateDummyArgs(value);
              value.apply(obj, args);
            } catch (e) {
              // Function threw an error - that's fine, we still observed its behavior
              __jsnabber_log(
                "function_discovery",
                `Function ${fullPath} threw: ${e.message}`,
              );
            }
          }
          // Recurse into objects (but not DOM elements or special objects)
          else if (typeof value === "object" && value !== null) {
            // Skip DOM-like objects and circular refs
            if (value === globalThis || value === window || value === document)
              continue;

            discoverAndExecute(value, fullPath, depth + 1);
          }
        } catch (e) {
          // Property access failed, skip it
        }
      }
    } catch (e) {
      // Object enumeration failed
    }
  }

  __jsnabber_log(
    "function_discovery",
    "Starting automatic function discovery...",
  );

  // 1. Try common entry points first
  const commonEntryPoints = [
    "main",
    "init",
    "start",
    "run",
    "execute",
    "onLoad",
    "onReady",
    "setup",
    "bootstrap",
    "launch",
    "begin",
    "entry",
  ];

  for (const name of commonEntryPoints) {
    if (typeof globalThis[name] === "function") {
      try {
        __jsnabber_log(
          "function_discovery",
          `Calling common entry point: ${name}()`,
        );
        globalThis[name]();
        executionCount++;
      } catch (e) {
        __jsnabber_log(
          "function_discovery",
          `Entry point ${name}() threw: ${e.message}`,
        );
      }
    }
  }

  // 2. Discover and execute all global functions
  discoverAndExecute(globalThis, "globalThis", 0);

  // 3. Check module.exports (Node.js style)
  if (typeof module !== "undefined" && module.exports) {
    discoverAndExecute(module.exports, "module.exports", 0);
  }

  // 4. Check window object specifically
  if (typeof window !== "undefined" && window !== globalThis) {
    discoverAndExecute(window, "window", 0);
  }

  __jsnabber_log(
    "function_discovery",
    `Function discovery complete. Executed ${executionCount} functions.`,
  );
})();
