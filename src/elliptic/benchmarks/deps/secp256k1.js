// Compiled with emcc --memory-init-file 0 -O3 secp256k1.c  -o secp256k1.js -s EXPORTED_FUNCTIONS="['_secp256k1_start','_secp256k1_ecdsa_sign','_secp256k1_ec_pubkey_create']"
// (emscripten 1.29.0)
// From https://github.com/bitcoin/secp256k1
/*
Copyright (c) 2013 Pieter Wuille

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
var Module;
if (!Module) Module = (typeof Module !== "undefined" ? Module : null) || {};
var moduleOverrides = {};
for (var key in Module) {
  if (Module.hasOwnProperty(key)) {
    moduleOverrides[key] = Module[key];
  }
}
var ENVIRONMENT_IS_NODE =
  typeof process === "object" && typeof require === "function";
var ENVIRONMENT_IS_WEB = typeof window === "object";
var ENVIRONMENT_IS_WORKER = typeof importScripts === "function";
var ENVIRONMENT_IS_SHELL =
  !ENVIRONMENT_IS_WEB && !ENVIRONMENT_IS_NODE && !ENVIRONMENT_IS_WORKER;
if (ENVIRONMENT_IS_NODE) {
  if (!Module["print"])
    Module["print"] = function print(x) {
      process["stdout"].write(x + "\n");
    };
  if (!Module["printErr"])
    Module["printErr"] = function printErr(x) {
      process["stderr"].write(x + "\n");
    };
  var nodeFS = require("test/test/node_modules/fs");
  var nodePath = require("path");
  Module["read"] = function read(filename, binary) {
    filename = nodePath["normalize"](filename);
    var ret = nodeFS["readFileSync"](filename);
    if (!ret && filename != nodePath["resolve"](filename)) {
      filename = path.join(__dirname, "..", "src", filename);
      ret = nodeFS["readFileSync"](filename);
    }
    if (ret && !binary) ret = ret.toString();
    return ret;
  };
  Module["readBinary"] = function readBinary(filename) {
    return Module["read"](filename, true);
  };
  Module["load"] = function load(f) {
    globalEval(read(f));
  };
  if (process["argv"].length > 1) {
    Module["thisProgram"] = process["argv"][1].replace(/\\/g, "/");
  } else {
    Module["thisProgram"] = "unknown-program";
  }
  Module["arguments"] = process["argv"].slice(2);
  if (typeof module !== "undefined") {
    module["exports"] = Module;
  }
  process["on"]("uncaughtException", function (ex) {
    if (!(ex instanceof ExitStatus)) {
      throw ex;
    }
  });
} else if (ENVIRONMENT_IS_SHELL) {
  if (!Module["print"]) Module["print"] = print;
  if (typeof printErr != "undefined") Module["printErr"] = printErr;
  if (typeof read != "undefined") {
    Module["read"] = read;
  } else {
    Module["read"] = function read() {
      throw "no read() available (jsc?)";
    };
  }
  Module["readBinary"] = function readBinary(f) {
    if (typeof readbuffer === "function") {
      return new Uint8Array(readbuffer(f));
    }
    var data = read(f, "binary");
    assert(typeof data === "object");
    return data;
  };
  if (typeof scriptArgs != "undefined") {
    Module["arguments"] = scriptArgs;
  } else if (typeof arguments != "undefined") {
    Module["arguments"] = arguments;
  }
  this["Module"] = Module;
} else if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
  Module["read"] = function read(url) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url, false);
    xhr.send(null);
    return xhr.responseText;
  };
  if (typeof arguments != "undefined") {
    Module["arguments"] = arguments;
  }
  if (typeof console !== "undefined") {
    if (!Module["print"])
      Module["print"] = function print(x) {
        console.log(x);
      };
    if (!Module["printErr"])
      Module["printErr"] = function printErr(x) {
        console.log(x);
      };
  } else {
    var TRY_USE_DUMP = false;
    if (!Module["print"])
      Module["print"] =
        TRY_USE_DUMP && typeof dump !== "undefined"
          ? function (x) {
              dump(x);
            }
          : function (x) {};
  }
  if (ENVIRONMENT_IS_WEB) {
    window["Module"] = Module;
  } else {
    Module["load"] = importScripts;
  }
} else {
  throw "Unknown runtime environment. Where are we?";
}
function globalEval(x) {
  eval.call(null, x);
}
if (!Module["load"] && Module["read"]) {
  Module["load"] = function load(f) {
    globalEval(Module["read"](f));
  };
}
if (!Module["print"]) {
  Module["print"] = function () {};
}
if (!Module["printErr"]) {
  Module["printErr"] = Module["print"];
}
if (!Module["arguments"]) {
  Module["arguments"] = [];
}
if (!Module["thisProgram"]) {
  Module["thisProgram"] = "./this.program";
}
Module.print = Module["print"];
Module.printErr = Module["printErr"];
Module["preRun"] = [];
Module["postRun"] = [];
for (var key in moduleOverrides) {
  if (moduleOverrides.hasOwnProperty(key)) {
    Module[key] = moduleOverrides[key];
  }
}
var Runtime = {
  setTempRet0: function (value) {
    tempRet0 = value;
  },
  getTempRet0: function () {
    return tempRet0;
  },
  stackSave: function () {
    return STACKTOP;
  },
  stackRestore: function (stackTop) {
    STACKTOP = stackTop;
  },
  getNativeTypeSize: function (type) {
    switch (type) {
      case "i1":
      case "i8":
        return 1;
      case "i16":
        return 2;
      case "i32":
        return 4;
      case "i64":
        return 8;
      case "float":
        return 4;
      case "double":
        return 8;
      default: {
        if (type[type.length - 1] === "*") {
          return Runtime.QUANTUM_SIZE;
        } else if (type[0] === "i") {
          var bits = parseInt(type.substr(1));
          assert(bits % 8 === 0);
          return bits / 8;
        } else {
          return 0;
        }
      }
    }
  },
  getNativeFieldSize: function (type) {
    return Math.max(Runtime.getNativeTypeSize(type), Runtime.QUANTUM_SIZE);
  },
  STACK_ALIGN: 16,
  getAlignSize: function (type, size, vararg) {
    if (!vararg && (type == "i64" || type == "double")) return 8;
    if (!type) return Math.min(size, 8);
    return Math.min(
      size || (type ? Runtime.getNativeFieldSize(type) : 0),
      Runtime.QUANTUM_SIZE
    );
  },
  dynCall: function (sig, ptr, args) {
    if (args && args.length) {
      if (!args.splice) args = Array.prototype.slice.call(args);
      args.splice(0, 0, ptr);
      return Module["dynCall_" + sig].apply(null, args);
    } else {
      return Module["dynCall_" + sig].call(null, ptr);
    }
  },
  functionPointers: [],
  addFunction: function (func) {
    for (var i = 0; i < Runtime.functionPointers.length; i++) {
      if (!Runtime.functionPointers[i]) {
        Runtime.functionPointers[i] = func;
        return 2 * (1 + i);
      }
    }
    throw "Finished up all reserved function pointers. Use a higher value for RESERVED_FUNCTION_POINTERS.";
  },
  removeFunction: function (index) {
    Runtime.functionPointers[(index - 2) / 2] = null;
  },
  getAsmConst: function (code, numArgs) {
    if (!Runtime.asmConstCache) Runtime.asmConstCache = {};
    var func = Runtime.asmConstCache[code];
    if (func) return func;
    var args = [];
    for (var i = 0; i < numArgs; i++) {
      args.push(String.fromCharCode(36) + i);
    }
    var source = Pointer_stringify(code);
    if (source[0] === '"') {
      if (source.indexOf('"', 1) === source.length - 1) {
        source = source.substr(1, source.length - 2);
      } else {
        abort(
          "invalid EM_ASM input |" +
            source +
            "|. Please use EM_ASM(..code..) (no quotes) or EM_ASM({ ..code($0).. }, input) (to input values)"
        );
      }
    }
    try {
      var evalled = eval(
        "(function(Module, FS) { return function(" +
          args.join(",") +
          "){ " +
          source +
          " } })"
      )(Module, typeof FS !== "undefined" ? FS : null);
    } catch (e) {
      Module.printErr(
        "error in executing inline EM_ASM code: " +
          e +
          " on: \n\n" +
          source +
          "\n\nwith args |" +
          args +
          "| (make sure to use the right one out of EM_ASM, EM_ASM_ARGS, etc.)"
      );
      throw e;
    }
    return (Runtime.asmConstCache[code] = evalled);
  },
  warnOnce: function (text) {
    if (!Runtime.warnOnce.shown) Runtime.warnOnce.shown = {};
    if (!Runtime.warnOnce.shown[text]) {
      Runtime.warnOnce.shown[text] = 1;
      Module.printErr(text);
    }
  },
  funcWrappers: {},
  getFuncWrapper: function (func, sig) {
    assert(sig);
    if (!Runtime.funcWrappers[sig]) {
      Runtime.funcWrappers[sig] = {};
    }
    var sigCache = Runtime.funcWrappers[sig];
    if (!sigCache[func]) {
      sigCache[func] = function dynCall_wrapper() {
        return Runtime.dynCall(sig, func, arguments);
      };
    }
    return sigCache[func];
  },
  UTF8Processor: function () {
    var buffer = [];
    var needed = 0;
    this.processCChar = function (code) {
      code = code & 255;
      if (buffer.length == 0) {
        if ((code & 128) == 0) {
          return String.fromCharCode(code);
        }
        buffer.push(code);
        if ((code & 224) == 192) {
          needed = 1;
        } else if ((code & 240) == 224) {
          needed = 2;
        } else {
          needed = 3;
        }
        return "";
      }
      if (needed) {
        buffer.push(code);
        needed--;
        if (needed > 0) return "";
      }
      var c1 = buffer[0];
      var c2 = buffer[1];
      var c3 = buffer[2];
      var c4 = buffer[3];
      var ret;
      if (buffer.length == 2) {
        ret = String.fromCharCode(((c1 & 31) << 6) | (c2 & 63));
      } else if (buffer.length == 3) {
        ret = String.fromCharCode(
          ((c1 & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63)
        );
      } else {
        var codePoint =
          ((c1 & 7) << 18) | ((c2 & 63) << 12) | ((c3 & 63) << 6) | (c4 & 63);
        ret = String.fromCharCode(
          (((codePoint - 65536) / 1024) | 0) + 55296,
          ((codePoint - 65536) % 1024) + 56320
        );
      }
      buffer.length = 0;
      return ret;
    };
    this.processJSString = function processJSString(string) {
      string = unescape(encodeURIComponent(string));
      var ret = [];
      for (var i = 0; i < string.length; i++) {
        ret.push(string.charCodeAt(i));
      }
      return ret;
    };
  },
  getCompilerSetting: function (name) {
    throw "You must build with -s RETAIN_COMPILER_SETTINGS=1 for Runtime.getCompilerSetting or emscripten_get_compiler_setting to work";
  },
  stackAlloc: function (size) {
    var ret = STACKTOP;
    STACKTOP = (STACKTOP + size) | 0;
    STACKTOP = (STACKTOP + 15) & -16;
    return ret;
  },
  staticAlloc: function (size) {
    var ret = STATICTOP;
    STATICTOP = (STATICTOP + size) | 0;
    STATICTOP = (STATICTOP + 15) & -16;
    return ret;
  },
  dynamicAlloc: function (size) {
    var ret = DYNAMICTOP;
    DYNAMICTOP = (DYNAMICTOP + size) | 0;
    DYNAMICTOP = (DYNAMICTOP + 15) & -16;
    if (DYNAMICTOP >= TOTAL_MEMORY) enlargeMemory();
    return ret;
  },
  alignMemory: function (size, quantum) {
    var ret = (size =
      Math.ceil(size / (quantum ? quantum : 16)) * (quantum ? quantum : 16));
    return ret;
  },
  makeBigInt: function (low, high, unsigned) {
    var ret = unsigned
      ? +(low >>> 0) + +(high >>> 0) * +4294967296
      : +(low >>> 0) + +(high | 0) * +4294967296;
    return ret;
  },
  GLOBAL_BASE: 8,
  QUANTUM_SIZE: 4,
  __dummy__: 0,
};
Module["Runtime"] = Runtime;
var __THREW__ = 0;
var ABORT = false;
var EXITSTATUS = 0;
var undef = 0;
var tempValue,
  tempInt,
  tempBigInt,
  tempInt2,
  tempBigInt2,
  tempPair,
  tempBigIntI,
  tempBigIntR,
  tempBigIntS,
  tempBigIntP,
  tempBigIntD,
  tempDouble,
  tempFloat;
var tempI64, tempI64b;
var tempRet0,
  tempRet1,
  tempRet2,
  tempRet3,
  tempRet4,
  tempRet5,
  tempRet6,
  tempRet7,
  tempRet8,
  tempRet9;
function assert(condition, text) {
  if (!condition) {
    abort("Assertion failed: " + text);
  }
}
var globalScope = this;
function getCFunc(ident) {
  var func = Module["_" + ident];
  if (!func) {
    try {
      func = eval("_" + ident);
    } catch (e) {}
  }
  assert(
    func,
    "Cannot call unknown function " +
      ident +
      " (perhaps LLVM optimizations or closure removed it?)"
  );
  return func;
}
var cwrap, ccall;
(function () {
  var JSfuncs = {
    stackSave: function () {
      Runtime.stackSave();
    },
    stackRestore: function () {
      Runtime.stackRestore();
    },
    arrayToC: function (arr) {
      var ret = Runtime.stackAlloc(arr.length);
      writeArrayToMemory(arr, ret);
      return ret;
    },
    stringToC: function (str) {
      var ret = 0;
      if (str !== null && str !== undefined && str !== 0) {
        ret = Runtime.stackAlloc((str.length << 2) + 1);
        writeStringToMemory(str, ret);
      }
      return ret;
    },
  };
  var toC = { string: JSfuncs["stringToC"], array: JSfuncs["arrayToC"] };
  ccall = function ccallFunc(ident, returnType, argTypes, args) {
    var func = getCFunc(ident);
    var cArgs = [];
    var stack = 0;
    if (args) {
      for (var i = 0; i < args.length; i++) {
        var converter = toC[argTypes[i]];
        if (converter) {
          if (stack === 0) stack = Runtime.stackSave();
          cArgs[i] = converter(args[i]);
        } else {
          cArgs[i] = args[i];
        }
      }
    }
    var ret = func.apply(null, cArgs);
    if (returnType === "string") ret = Pointer_stringify(ret);
    if (stack !== 0) Runtime.stackRestore(stack);
    return ret;
  };
  var sourceRegex = /^function\s*\(([^)]*)\)\s*{\s*([^*]*?)[\s;]*(?:return\s*(.*?)[;\s]*)?}$/;
  function parseJSFunc(jsfunc) {
    var parsed = jsfunc.toString().match(sourceRegex).slice(1);
    return { arguments: parsed[0], body: parsed[1], returnValue: parsed[2] };
  }
  var JSsource = {};
  for (var fun in JSfuncs) {
    if (JSfuncs.hasOwnProperty(fun)) {
      JSsource[fun] = parseJSFunc(JSfuncs[fun]);
    }
  }
  cwrap = function cwrap(ident, returnType, argTypes) {
    argTypes = argTypes || [];
    var cfunc = getCFunc(ident);
    var numericArgs = argTypes.every(function (type) {
      return type === "number";
    });
    var numericRet = returnType !== "string";
    if (numericRet && numericArgs) {
      return cfunc;
    }
    var argNames = argTypes.map(function (x, i) {
      return "$" + i;
    });
    var funcstr = "(function(" + argNames.join(",") + ") {";
    var nargs = argTypes.length;
    if (!numericArgs) {
      funcstr += "var stack = " + JSsource["stackSave"].body + ";";
      for (var i = 0; i < nargs; i++) {
        var arg = argNames[i],
          type = argTypes[i];
        if (type === "number") continue;
        var convertCode = JSsource[type + "ToC"];
        funcstr += "var " + convertCode.arguments + " = " + arg + ";";
        funcstr += convertCode.body + ";";
        funcstr += arg + "=" + convertCode.returnValue + ";";
      }
    }
    var cfuncname = parseJSFunc(function () {
      return cfunc;
    }).returnValue;
    funcstr += "var ret = " + cfuncname + "(" + argNames.join(",") + ");";
    if (!numericRet) {
      var strgfy = parseJSFunc(function () {
        return Pointer_stringify;
      }).returnValue;
      funcstr += "ret = " + strgfy + "(ret);";
    }
    if (!numericArgs) {
      funcstr += JSsource["stackRestore"].body.replace("()", "(stack)") + ";";
    }
    funcstr += "return ret})";
    return eval(funcstr);
  };
})();
Module["cwrap"] = cwrap;
Module["ccall"] = ccall;
function setValue(ptr, value, type, noSafe) {
  type = type || "i8";
  if (type.charAt(type.length - 1) === "*") type = "i32";
  switch (type) {
    case "i1":
      HEAP8[ptr >> 0] = value;
      break;
    case "i8":
      HEAP8[ptr >> 0] = value;
      break;
    case "i16":
      HEAP16[ptr >> 1] = value;
      break;
    case "i32":
      HEAP32[ptr >> 2] = value;
      break;
    case "i64":
      (tempI64 = [
        value >>> 0,
        ((tempDouble = value),
        +Math_abs(tempDouble) >= +1
          ? tempDouble > +0
            ? (Math_min(+Math_floor(tempDouble / +4294967296), +4294967295) |
                0) >>>
              0
            : ~~+Math_ceil(
                (tempDouble - +(~~tempDouble >>> 0)) / +4294967296
              ) >>> 0
          : 0),
      ]),
        (HEAP32[ptr >> 2] = tempI64[0]),
        (HEAP32[(ptr + 4) >> 2] = tempI64[1]);
      break;
    case "float":
      HEAPF32[ptr >> 2] = value;
      break;
    case "double":
      HEAPF64[ptr >> 3] = value;
      break;
    default:
      abort("invalid type for setValue: " + type);
  }
}
Module["setValue"] = setValue;
function getValue(ptr, type, noSafe) {
  type = type || "i8";
  if (type.charAt(type.length - 1) === "*") type = "i32";
  switch (type) {
    case "i1":
      return HEAP8[ptr >> 0];
    case "i8":
      return HEAP8[ptr >> 0];
    case "i16":
      return HEAP16[ptr >> 1];
    case "i32":
      return HEAP32[ptr >> 2];
    case "i64":
      return HEAP32[ptr >> 2];
    case "float":
      return HEAPF32[ptr >> 2];
    case "double":
      return HEAPF64[ptr >> 3];
    default:
      abort("invalid type for setValue: " + type);
  }
  return null;
}
Module["getValue"] = getValue;
var ALLOC_NORMAL = 0;
var ALLOC_STACK = 1;
var ALLOC_STATIC = 2;
var ALLOC_DYNAMIC = 3;
var ALLOC_NONE = 4;
Module["ALLOC_NORMAL"] = ALLOC_NORMAL;
Module["ALLOC_STACK"] = ALLOC_STACK;
Module["ALLOC_STATIC"] = ALLOC_STATIC;
Module["ALLOC_DYNAMIC"] = ALLOC_DYNAMIC;
Module["ALLOC_NONE"] = ALLOC_NONE;
function allocate(slab, types, allocator, ptr) {
  var zeroinit, size;
  if (typeof slab === "number") {
    zeroinit = true;
    size = slab;
  } else {
    zeroinit = false;
    size = slab.length;
  }
  var singleType = typeof types === "string" ? types : null;
  var ret;
  if (allocator == ALLOC_NONE) {
    ret = ptr;
  } else {
    ret = [
      _malloc,
      Runtime.stackAlloc,
      Runtime.staticAlloc,
      Runtime.dynamicAlloc,
    ][allocator === undefined ? ALLOC_STATIC : allocator](
      Math.max(size, singleType ? 1 : types.length)
    );
  }
  if (zeroinit) {
    var ptr = ret,
      stop;
    assert((ret & 3) == 0);
    stop = ret + (size & ~3);
    for (; ptr < stop; ptr += 4) {
      HEAP32[ptr >> 2] = 0;
    }
    stop = ret + size;
    while (ptr < stop) {
      HEAP8[ptr++ >> 0] = 0;
    }
    return ret;
  }
  if (singleType === "i8") {
    if (slab.subarray || slab.slice) {
      HEAPU8.set(slab, ret);
    } else {
      HEAPU8.set(new Uint8Array(slab), ret);
    }
    return ret;
  }
  var i = 0,
    type,
    typeSize,
    previousType;
  while (i < size) {
    var curr = slab[i];
    if (typeof curr === "function") {
      curr = Runtime.getFunctionIndex(curr);
    }
    type = singleType || types[i];
    if (type === 0) {
      i++;
      continue;
    }
    if (type == "i64") type = "i32";
    setValue(ret + i, curr, type);
    if (previousType !== type) {
      typeSize = Runtime.getNativeTypeSize(type);
      previousType = type;
    }
    i += typeSize;
  }
  return ret;
}
Module["allocate"] = allocate;
function Pointer_stringify(ptr, length) {
  if (length === 0 || !ptr) return "";
  var hasUtf = false;
  var t;
  var i = 0;
  while (1) {
    t = HEAPU8[(ptr + i) >> 0];
    if (t >= 128) hasUtf = true;
    else if (t == 0 && !length) break;
    i++;
    if (length && i == length) break;
  }
  if (!length) length = i;
  var ret = "";
  if (!hasUtf) {
    var MAX_CHUNK = 1024;
    var curr;
    while (length > 0) {
      curr = String.fromCharCode.apply(
        String,
        HEAPU8.subarray(ptr, ptr + Math.min(length, MAX_CHUNK))
      );
      ret = ret ? ret + curr : curr;
      ptr += MAX_CHUNK;
      length -= MAX_CHUNK;
    }
    return ret;
  }
  var utf8 = new Runtime.UTF8Processor();
  for (i = 0; i < length; i++) {
    t = HEAPU8[(ptr + i) >> 0];
    ret += utf8.processCChar(t);
  }
  return ret;
}
Module["Pointer_stringify"] = Pointer_stringify;
function UTF16ToString(ptr) {
  var i = 0;
  var str = "";
  while (1) {
    var codeUnit = HEAP16[(ptr + i * 2) >> 1];
    if (codeUnit == 0) return str;
    ++i;
    str += String.fromCharCode(codeUnit);
  }
}
Module["UTF16ToString"] = UTF16ToString;
function stringToUTF16(str, outPtr) {
  for (var i = 0; i < str.length; ++i) {
    var codeUnit = str.charCodeAt(i);
    HEAP16[(outPtr + i * 2) >> 1] = codeUnit;
  }
  HEAP16[(outPtr + str.length * 2) >> 1] = 0;
}
Module["stringToUTF16"] = stringToUTF16;
function UTF32ToString(ptr) {
  var i = 0;
  var str = "";
  while (1) {
    var utf32 = HEAP32[(ptr + i * 4) >> 2];
    if (utf32 == 0) return str;
    ++i;
    if (utf32 >= 65536) {
      var ch = utf32 - 65536;
      str += String.fromCharCode(55296 | (ch >> 10), 56320 | (ch & 1023));
    } else {
      str += String.fromCharCode(utf32);
    }
  }
}
Module["UTF32ToString"] = UTF32ToString;
function stringToUTF32(str, outPtr) {
  var iChar = 0;
  for (var iCodeUnit = 0; iCodeUnit < str.length; ++iCodeUnit) {
    var codeUnit = str.charCodeAt(iCodeUnit);
    if (codeUnit >= 55296 && codeUnit <= 57343) {
      var trailSurrogate = str.charCodeAt(++iCodeUnit);
      codeUnit = (65536 + ((codeUnit & 1023) << 10)) | (trailSurrogate & 1023);
    }
    HEAP32[(outPtr + iChar * 4) >> 2] = codeUnit;
    ++iChar;
  }
  HEAP32[(outPtr + iChar * 4) >> 2] = 0;
}
Module["stringToUTF32"] = stringToUTF32;
function demangle(func) {
  var hasLibcxxabi = !!Module["___cxa_demangle"];
  if (hasLibcxxabi) {
    try {
      var buf = _malloc(func.length);
      writeStringToMemory(func.substr(1), buf);
      var status = _malloc(4);
      var ret = Module["___cxa_demangle"](buf, 0, 0, status);
      if (getValue(status, "i32") === 0 && ret) {
        return Pointer_stringify(ret);
      }
    } catch (e) {
    } finally {
      if (buf) _free(buf);
      if (status) _free(status);
      if (ret) _free(ret);
    }
  }
  var i = 3;
  var basicTypes = {
    v: "void",
    b: "bool",
    c: "char",
    s: "short",
    i: "int",
    l: "long",
    f: "float",
    d: "double",
    w: "wchar_t",
    a: "signed char",
    h: "unsigned char",
    t: "unsigned short",
    j: "unsigned int",
    m: "unsigned long",
    x: "long long",
    y: "unsigned long long",
    z: "...",
  };
  var subs = [];
  var first = true;
  function dump(x) {
    if (x) Module.print(x);
    Module.print(func);
    var pre = "";
    for (var a = 0; a < i; a++) pre += " ";
    Module.print(pre + "^");
  }
  function parseNested() {
    i++;
    if (func[i] === "K") i++;
    var parts = [];
    while (func[i] !== "E") {
      if (func[i] === "S") {
        i++;
        var next = func.indexOf("_", i);
        var num = func.substring(i, next) || 0;
        parts.push(subs[num] || "?");
        i = next + 1;
        continue;
      }
      if (func[i] === "C") {
        parts.push(parts[parts.length - 1]);
        i += 2;
        continue;
      }
      var size = parseInt(func.substr(i));
      var pre = size.toString().length;
      if (!size || !pre) {
        i--;
        break;
      }
      var curr = func.substr(i + pre, size);
      parts.push(curr);
      subs.push(curr);
      i += pre + size;
    }
    i++;
    return parts;
  }
  function parse(rawList, limit, allowVoid) {
    limit = limit || Infinity;
    var ret = "",
      list = [];
    function flushList() {
      return "(" + list.join(", ") + ")";
    }
    var name;
    if (func[i] === "N") {
      name = parseNested().join("::");
      limit--;
      if (limit === 0) return rawList ? [name] : name;
    } else {
      if (func[i] === "K" || (first && func[i] === "L")) i++;
      var size = parseInt(func.substr(i));
      if (size) {
        var pre = size.toString().length;
        name = func.substr(i + pre, size);
        i += pre + size;
      }
    }
    first = false;
    if (func[i] === "I") {
      i++;
      var iList = parse(true);
      var iRet = parse(true, 1, true);
      ret += iRet[0] + " " + name + "<" + iList.join(", ") + ">";
    } else {
      ret = name;
    }
    paramLoop: while (i < func.length && limit-- > 0) {
      var c = func[i++];
      if (c in basicTypes) {
        list.push(basicTypes[c]);
      } else {
        switch (c) {
          case "P":
            list.push(parse(true, 1, true)[0] + "*");
            break;
          case "R":
            list.push(parse(true, 1, true)[0] + "&");
            break;
          case "L": {
            i++;
            var end = func.indexOf("E", i);
            var size = end - i;
            list.push(func.substr(i, size));
            i += size + 2;
            break;
          }
          case "A": {
            var size = parseInt(func.substr(i));
            i += size.toString().length;
            if (func[i] !== "_") throw "?";
            i++;
            list.push(parse(true, 1, true)[0] + " [" + size + "]");
            break;
          }
          case "E":
            break paramLoop;
          default:
            ret += "?" + c;
            break paramLoop;
        }
      }
    }
    if (!allowVoid && list.length === 1 && list[0] === "void") list = [];
    if (rawList) {
      if (ret) {
        list.push(ret + "?");
      }
      return list;
    } else {
      return ret + flushList();
    }
  }
  var parsed = func;
  try {
    if (func == "Object._main" || func == "_main") {
      return "main()";
    }
    if (typeof func === "number") func = Pointer_stringify(func);
    if (func[0] !== "_") return func;
    if (func[1] !== "_") return func;
    if (func[2] !== "Z") return func;
    switch (func[3]) {
      case "n":
        return "operator new()";
      case "d":
        return "operator delete()";
    }
    parsed = parse();
  } catch (e) {
    parsed += "?";
  }
  if (parsed.indexOf("?") >= 0 && !hasLibcxxabi) {
    Runtime.warnOnce(
      "warning: a problem occurred in builtin C++ name demangling; build with  -s DEMANGLE_SUPPORT=1  to link in libcxxabi demangling"
    );
  }
  return parsed;
}
function demangleAll(text) {
  return text.replace(/__Z[\w\d_]+/g, function (x) {
    var y = demangle(x);
    return x === y ? x : x + " [" + y + "]";
  });
}
function jsStackTrace() {
  var err = new Error();
  if (!err.stack) {
    try {
      throw new Error(0);
    } catch (e) {
      err = e;
    }
    if (!err.stack) {
      return "(no stack trace available)";
    }
  }
  return err.stack.toString();
}
function stackTrace() {
  return demangleAll(jsStackTrace());
}
Module["stackTrace"] = stackTrace;
var PAGE_SIZE = 4096;
function alignMemoryPage(x) {
  return (x + 4095) & -4096;
}
var HEAP;
var HEAP8, HEAPU8, HEAP16, HEAPU16, HEAP32, HEAPU32, HEAPF32, HEAPF64;
var STATIC_BASE = 0,
  STATICTOP = 0,
  staticSealed = false;
var STACK_BASE = 0,
  STACKTOP = 0,
  STACK_MAX = 0;
var DYNAMIC_BASE = 0,
  DYNAMICTOP = 0;
function enlargeMemory() {
  abort(
    "Cannot enlarge memory arrays. Either (1) compile with -s TOTAL_MEMORY=X with X higher than the current value " +
      TOTAL_MEMORY +
      ", (2) compile with ALLOW_MEMORY_GROWTH which adjusts the size at runtime but prevents some optimizations, or (3) set Module.TOTAL_MEMORY before the program runs."
  );
}
var TOTAL_STACK = Module["TOTAL_STACK"] || 5242880;
var TOTAL_MEMORY = Module["TOTAL_MEMORY"] || 16777216;
var FAST_MEMORY = Module["FAST_MEMORY"] || 2097152;
var totalMemory = 64 * 1024;
while (totalMemory < TOTAL_MEMORY || totalMemory < 2 * TOTAL_STACK) {
  if (totalMemory < 16 * 1024 * 1024) {
    totalMemory *= 2;
  } else {
    totalMemory += 16 * 1024 * 1024;
  }
}
if (totalMemory !== TOTAL_MEMORY) {
  Module.printErr(
    "increasing TOTAL_MEMORY to " +
      totalMemory +
      " to be compliant with the asm.js spec"
  );
  TOTAL_MEMORY = totalMemory;
}
assert(
  typeof Int32Array !== "undefined" &&
    typeof Float64Array !== "undefined" &&
    !!new Int32Array(1)["subarray"] &&
    !!new Int32Array(1)["set"],
  "JS engine does not provide full typed array support"
);
var buffer = new ArrayBuffer(TOTAL_MEMORY);
HEAP8 = new Int8Array(buffer);
HEAP16 = new Int16Array(buffer);
HEAP32 = new Int32Array(buffer);
HEAPU8 = new Uint8Array(buffer);
HEAPU16 = new Uint16Array(buffer);
HEAPU32 = new Uint32Array(buffer);
HEAPF32 = new Float32Array(buffer);
HEAPF64 = new Float64Array(buffer);
HEAP32[0] = 255;
assert(
  HEAPU8[0] === 255 && HEAPU8[3] === 0,
  "Typed arrays 2 must be run on a little-endian system"
);
Module["HEAP"] = HEAP;
Module["buffer"] = buffer;
Module["HEAP8"] = HEAP8;
Module["HEAP16"] = HEAP16;
Module["HEAP32"] = HEAP32;
Module["HEAPU8"] = HEAPU8;
Module["HEAPU16"] = HEAPU16;
Module["HEAPU32"] = HEAPU32;
Module["HEAPF32"] = HEAPF32;
Module["HEAPF64"] = HEAPF64;
function callRuntimeCallbacks(callbacks) {
  while (callbacks.length > 0) {
    var callback = callbacks.shift();
    if (typeof callback == "function") {
      callback();
      continue;
    }
    var func = callback.func;
    if (typeof func === "number") {
      if (callback.arg === undefined) {
        Runtime.dynCall("v", func);
      } else {
        Runtime.dynCall("vi", func, [callback.arg]);
      }
    } else {
      func(callback.arg === undefined ? null : callback.arg);
    }
  }
}
var __ATPRERUN__ = [];
var __ATINIT__ = [];
var __ATMAIN__ = [];
var __ATEXIT__ = [];
var __ATPOSTRUN__ = [];
var runtimeInitialized = false;
var runtimeExited = false;
function preRun() {
  if (Module["preRun"]) {
    if (typeof Module["preRun"] == "function")
      Module["preRun"] = [Module["preRun"]];
    while (Module["preRun"].length) {
      addOnPreRun(Module["preRun"].shift());
    }
  }
  callRuntimeCallbacks(__ATPRERUN__);
}
function ensureInitRuntime() {
  if (runtimeInitialized) return;
  runtimeInitialized = true;
  callRuntimeCallbacks(__ATINIT__);
}
function preMain() {
  callRuntimeCallbacks(__ATMAIN__);
}
function exitRuntime() {
  callRuntimeCallbacks(__ATEXIT__);
  runtimeExited = true;
}
function postRun() {
  if (Module["postRun"]) {
    if (typeof Module["postRun"] == "function")
      Module["postRun"] = [Module["postRun"]];
    while (Module["postRun"].length) {
      addOnPostRun(Module["postRun"].shift());
    }
  }
  callRuntimeCallbacks(__ATPOSTRUN__);
}
function addOnPreRun(cb) {
  __ATPRERUN__.unshift(cb);
}
Module["addOnPreRun"] = Module.addOnPreRun = addOnPreRun;
function addOnInit(cb) {
  __ATINIT__.unshift(cb);
}
Module["addOnInit"] = Module.addOnInit = addOnInit;
function addOnPreMain(cb) {
  __ATMAIN__.unshift(cb);
}
Module["addOnPreMain"] = Module.addOnPreMain = addOnPreMain;
function addOnExit(cb) {
  __ATEXIT__.unshift(cb);
}
Module["addOnExit"] = Module.addOnExit = addOnExit;
function addOnPostRun(cb) {
  __ATPOSTRUN__.unshift(cb);
}
Module["addOnPostRun"] = Module.addOnPostRun = addOnPostRun;
function intArrayFromString(stringy, dontAddNull, length) {
  var ret = new Runtime.UTF8Processor().processJSString(stringy);
  if (length) {
    ret.length = length;
  }
  if (!dontAddNull) {
    ret.push(0);
  }
  return ret;
}
Module["intArrayFromString"] = intArrayFromString;
function intArrayToString(array) {
  var ret = [];
  for (var i = 0; i < array.length; i++) {
    var chr = array[i];
    if (chr > 255) {
      chr &= 255;
    }
    ret.push(String.fromCharCode(chr));
  }
  return ret.join("");
}
Module["intArrayToString"] = intArrayToString;
function writeStringToMemory(string, buffer, dontAddNull) {
  var array = intArrayFromString(string, dontAddNull);
  var i = 0;
  while (i < array.length) {
    var chr = array[i];
    HEAP8[(buffer + i) >> 0] = chr;
    i = i + 1;
  }
}
Module["writeStringToMemory"] = writeStringToMemory;
function writeArrayToMemory(array, buffer) {
  for (var i = 0; i < array.length; i++) {
    HEAP8[(buffer + i) >> 0] = array[i];
  }
}
Module["writeArrayToMemory"] = writeArrayToMemory;
function writeAsciiToMemory(str, buffer, dontAddNull) {
  for (var i = 0; i < str.length; i++) {
    HEAP8[(buffer + i) >> 0] = str.charCodeAt(i);
  }
  if (!dontAddNull) HEAP8[(buffer + str.length) >> 0] = 0;
}
Module["writeAsciiToMemory"] = writeAsciiToMemory;
function unSign(value, bits, ignore) {
  if (value >= 0) {
    return value;
  }
  return bits <= 32
    ? 2 * Math.abs(1 << (bits - 1)) + value
    : Math.pow(2, bits) + value;
}
function reSign(value, bits, ignore) {
  if (value <= 0) {
    return value;
  }
  var half = bits <= 32 ? Math.abs(1 << (bits - 1)) : Math.pow(2, bits - 1);
  if (value >= half && (bits <= 32 || value > half)) {
    value = -2 * half + value;
  }
  return value;
}
if (!Math["imul"] || Math["imul"](4294967295, 5) !== -5)
  Math["imul"] = function imul(a, b) {
    var ah = a >>> 16;
    var al = a & 65535;
    var bh = b >>> 16;
    var bl = b & 65535;
    return (al * bl + ((ah * bl + al * bh) << 16)) | 0;
  };
Math.imul = Math["imul"];
var Math_abs = Math.abs;
var Math_cos = Math.cos;
var Math_sin = Math.sin;
var Math_tan = Math.tan;
var Math_acos = Math.acos;
var Math_asin = Math.asin;
var Math_atan = Math.atan;
var Math_atan2 = Math.atan2;
var Math_exp = Math.exp;
var Math_log = Math.log;
var Math_sqrt = Math.sqrt;
var Math_ceil = Math.ceil;
var Math_floor = Math.floor;
var Math_pow = Math.pow;
var Math_imul = Math.imul;
var Math_fround = Math.fround;
var Math_min = Math.min;
var runDependencies = 0;
var runDependencyWatcher = null;
var dependenciesFulfilled = null;
function addRunDependency(id) {
  runDependencies++;
  if (Module["monitorRunDependencies"]) {
    Module["monitorRunDependencies"](runDependencies);
  }
}
Module["addRunDependency"] = addRunDependency;
function removeRunDependency(id) {
  runDependencies--;
  if (Module["monitorRunDependencies"]) {
    Module["monitorRunDependencies"](runDependencies);
  }
  if (runDependencies == 0) {
    if (runDependencyWatcher !== null) {
      clearInterval(runDependencyWatcher);
      runDependencyWatcher = null;
    }
    if (dependenciesFulfilled) {
      var callback = dependenciesFulfilled;
      dependenciesFulfilled = null;
      callback();
    }
  }
}
Module["removeRunDependency"] = removeRunDependency;
Module["preloadedImages"] = {};
Module["preloadedAudios"] = {};
var memoryInitializer = null;
STATIC_BASE = 8;
STATICTOP = STATIC_BASE + 1152;
__ATINIT__.push();
allocate(
  [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    37,
    115,
    58,
    37,
    100,
    58,
    32,
    37,
    115,
    10,
    0,
    0,
    0,
    0,
    0,
    0,
    115,
    101,
    99,
    112,
    50,
    53,
    54,
    107,
    49,
    46,
    99,
    0,
    0,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    109,
    115,
    103,
    51,
    50,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    112,
    117,
    98,
    107,
    101,
    121,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    115,
    101,
    99,
    112,
    50,
    53,
    54,
    107,
    49,
    95,
    101,
    99,
    109,
    117,
    108,
    116,
    95,
    103,
    101,
    110,
    95,
    99,
    111,
    110,
    115,
    116,
    115,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    115,
    105,
    103,
    110,
    97,
    116,
    117,
    114,
    101,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    115,
    105,
    103,
    110,
    97,
    116,
    117,
    114,
    101,
    108,
    101,
    110,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    115,
    101,
    99,
    107,
    101,
    121,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    112,
    117,
    98,
    107,
    101,
    121,
    108,
    101,
    110,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    128,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    152,
    23,
    248,
    2,
    197,
    86,
    160,
    0,
    159,
    149,
    141,
    2,
    56,
    183,
    108,
    3,
    252,
    155,
    2,
    3,
    193,
    194,
    161,
    3,
    92,
    41,
    6,
    2,
    86,
    177,
    238,
    2,
    220,
    249,
    126,
    2,
    153,
    111,
    30,
    0,
    184,
    212,
    16,
    3,
    254,
    35,
    244,
    1,
    196,
    153,
    65,
    1,
    21,
    154,
    34,
    1,
    180,
    23,
    253,
    0,
    42,
    66,
    132,
    3,
    192,
    191,
    79,
    2,
    118,
    149,
    17,
    3,
    163,
    38,
    119,
    2,
    182,
    14,
    18,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    46,
    47,
    117,
    116,
    105,
    108,
    46,
    104,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    116,
    101,
    115,
    116,
    32,
    99,
    111,
    110,
    100,
    105,
    116,
    105,
    111,
    110,
    32,
    102,
    97,
    105,
    108,
    101,
    100,
    58,
    32,
    114,
    101,
    116,
    32,
    33,
    61,
    32,
    78,
    85,
    76,
    76,
    0,
    0,
    0,
    0,
    0,
    0,
    84,
    104,
    101,
    32,
    115,
    99,
    97,
    108,
    97,
    114,
    32,
    102,
    111,
    114,
    32,
    116,
    104,
    105,
    115,
    32,
    120,
    32,
    105,
    115,
    32,
    117,
    110,
    107,
    110,
    111,
    119,
    110,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
  ],
  "i8",
  ALLOC_NONE,
  Runtime.GLOBAL_BASE
);
var tempDoublePtr = Runtime.alignMemory(allocate(12, "i8", ALLOC_STATIC), 8);
assert(tempDoublePtr % 8 == 0);
function copyTempFloat(ptr) {
  HEAP8[tempDoublePtr] = HEAP8[ptr];
  HEAP8[tempDoublePtr + 1] = HEAP8[ptr + 1];
  HEAP8[tempDoublePtr + 2] = HEAP8[ptr + 2];
  HEAP8[tempDoublePtr + 3] = HEAP8[ptr + 3];
}
function copyTempDouble(ptr) {
  HEAP8[tempDoublePtr] = HEAP8[ptr];
  HEAP8[tempDoublePtr + 1] = HEAP8[ptr + 1];
  HEAP8[tempDoublePtr + 2] = HEAP8[ptr + 2];
  HEAP8[tempDoublePtr + 3] = HEAP8[ptr + 3];
  HEAP8[tempDoublePtr + 4] = HEAP8[ptr + 4];
  HEAP8[tempDoublePtr + 5] = HEAP8[ptr + 5];
  HEAP8[tempDoublePtr + 6] = HEAP8[ptr + 6];
  HEAP8[tempDoublePtr + 7] = HEAP8[ptr + 7];
}
var ___errno_state = 0;
function ___setErrNo(value) {
  HEAP32[___errno_state >> 2] = value;
  return value;
}
var ERRNO_CODES = {
  EPERM: 1,
  ENOENT: 2,
  ESRCH: 3,
  EINTR: 4,
  EIO: 5,
  ENXIO: 6,
  E2BIG: 7,
  ENOEXEC: 8,
  EBADF: 9,
  ECHILD: 10,
  EAGAIN: 11,
  EWOULDBLOCK: 11,
  ENOMEM: 12,
  EACCES: 13,
  EFAULT: 14,
  ENOTBLK: 15,
  EBUSY: 16,
  EEXIST: 17,
  EXDEV: 18,
  ENODEV: 19,
  ENOTDIR: 20,
  EISDIR: 21,
  EINVAL: 22,
  ENFILE: 23,
  EMFILE: 24,
  ENOTTY: 25,
  ETXTBSY: 26,
  EFBIG: 27,
  ENOSPC: 28,
  ESPIPE: 29,
  EROFS: 30,
  EMLINK: 31,
  EPIPE: 32,
  EDOM: 33,
  ERANGE: 34,
  ENOMSG: 42,
  EIDRM: 43,
  ECHRNG: 44,
  EL2NSYNC: 45,
  EL3HLT: 46,
  EL3RST: 47,
  ELNRNG: 48,
  EUNATCH: 49,
  ENOCSI: 50,
  EL2HLT: 51,
  EDEADLK: 35,
  ENOLCK: 37,
  EBADE: 52,
  EBADR: 53,
  EXFULL: 54,
  ENOANO: 55,
  EBADRQC: 56,
  EBADSLT: 57,
  EDEADLOCK: 35,
  EBFONT: 59,
  ENOSTR: 60,
  ENODATA: 61,
  ETIME: 62,
  ENOSR: 63,
  ENONET: 64,
  ENOPKG: 65,
  EREMOTE: 66,
  ENOLINK: 67,
  EADV: 68,
  ESRMNT: 69,
  ECOMM: 70,
  EPROTO: 71,
  EMULTIHOP: 72,
  EDOTDOT: 73,
  EBADMSG: 74,
  ENOTUNIQ: 76,
  EBADFD: 77,
  EREMCHG: 78,
  ELIBACC: 79,
  ELIBBAD: 80,
  ELIBSCN: 81,
  ELIBMAX: 82,
  ELIBEXEC: 83,
  ENOSYS: 38,
  ENOTEMPTY: 39,
  ENAMETOOLONG: 36,
  ELOOP: 40,
  EOPNOTSUPP: 95,
  EPFNOSUPPORT: 96,
  ECONNRESET: 104,
  ENOBUFS: 105,
  EAFNOSUPPORT: 97,
  EPROTOTYPE: 91,
  ENOTSOCK: 88,
  ENOPROTOOPT: 92,
  ESHUTDOWN: 108,
  ECONNREFUSED: 111,
  EADDRINUSE: 98,
  ECONNABORTED: 103,
  ENETUNREACH: 101,
  ENETDOWN: 100,
  ETIMEDOUT: 110,
  EHOSTDOWN: 112,
  EHOSTUNREACH: 113,
  EINPROGRESS: 115,
  EALREADY: 114,
  EDESTADDRREQ: 89,
  EMSGSIZE: 90,
  EPROTONOSUPPORT: 93,
  ESOCKTNOSUPPORT: 94,
  EADDRNOTAVAIL: 99,
  ENETRESET: 102,
  EISCONN: 106,
  ENOTCONN: 107,
  ETOOMANYREFS: 109,
  EUSERS: 87,
  EDQUOT: 122,
  ESTALE: 116,
  ENOTSUP: 95,
  ENOMEDIUM: 123,
  EILSEQ: 84,
  EOVERFLOW: 75,
  ECANCELED: 125,
  ENOTRECOVERABLE: 131,
  EOWNERDEAD: 130,
  ESTRPIPE: 86,
};
function _sysconf(name) {
  switch (name) {
    case 30:
      return PAGE_SIZE;
    case 132:
    case 133:
    case 12:
    case 137:
    case 138:
    case 15:
    case 235:
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 149:
    case 13:
    case 10:
    case 236:
    case 153:
    case 9:
    case 21:
    case 22:
    case 159:
    case 154:
    case 14:
    case 77:
    case 78:
    case 139:
    case 80:
    case 81:
    case 79:
    case 82:
    case 68:
    case 67:
    case 164:
    case 11:
    case 29:
    case 47:
    case 48:
    case 95:
    case 52:
    case 51:
    case 46:
      return 200809;
    case 27:
    case 246:
    case 127:
    case 128:
    case 23:
    case 24:
    case 160:
    case 161:
    case 181:
    case 182:
    case 242:
    case 183:
    case 184:
    case 243:
    case 244:
    case 245:
    case 165:
    case 178:
    case 179:
    case 49:
    case 50:
    case 168:
    case 169:
    case 175:
    case 170:
    case 171:
    case 172:
    case 97:
    case 76:
    case 32:
    case 173:
    case 35:
      return -1;
    case 176:
    case 177:
    case 7:
    case 155:
    case 8:
    case 157:
    case 125:
    case 126:
    case 92:
    case 93:
    case 129:
    case 130:
    case 131:
    case 94:
    case 91:
      return 1;
    case 74:
    case 60:
    case 69:
    case 70:
    case 4:
      return 1024;
    case 31:
    case 42:
    case 72:
      return 32;
    case 87:
    case 26:
    case 33:
      return 2147483647;
    case 34:
    case 1:
      return 47839;
    case 38:
    case 36:
      return 99;
    case 43:
    case 37:
      return 2048;
    case 0:
      return 2097152;
    case 3:
      return 65536;
    case 28:
      return 32768;
    case 44:
      return 32767;
    case 75:
      return 16384;
    case 39:
      return 1e3;
    case 89:
      return 700;
    case 71:
      return 256;
    case 40:
      return 255;
    case 2:
      return 100;
    case 180:
      return 64;
    case 25:
      return 20;
    case 5:
      return 16;
    case 6:
      return 6;
    case 73:
      return 4;
    case 84: {
      if (typeof navigator === "object")
        return navigator["hardwareConcurrency"] || 1;
      return 1;
    }
  }
  ___setErrNo(ERRNO_CODES.EINVAL);
  return -1;
}
Module["_i64Add"] = _i64Add;
Module["_memset"] = _memset;
function ___errno_location() {
  return ___errno_state;
}
Module["_bitshift64Lshr"] = _bitshift64Lshr;
Module["_bitshift64Shl"] = _bitshift64Shl;
function _abort() {
  Module["abort"]();
}
var ERRNO_MESSAGES = {
  0: "Success",
  1: "Not super-user",
  2: "No such file or directory",
  3: "No such process",
  4: "Interrupted system call",
  5: "I/O error",
  6: "No such device or address",
  7: "Arg list too long",
  8: "Exec format error",
  9: "Bad file number",
  10: "No children",
  11: "No more processes",
  12: "Not enough core",
  13: "Permission denied",
  14: "Bad address",
  15: "Block device required",
  16: "Mount device busy",
  17: "File exists",
  18: "Cross-device link",
  19: "No such device",
  20: "Not a directory",
  21: "Is a directory",
  22: "Invalid argument",
  23: "Too many open files in system",
  24: "Too many open files",
  25: "Not a typewriter",
  26: "Text file busy",
  27: "File too large",
  28: "No space left on device",
  29: "Illegal seek",
  30: "Read only file system",
  31: "Too many links",
  32: "Broken pipe",
  33: "Math arg out of domain of func",
  34: "Math result not representable",
  35: "File locking deadlock error",
  36: "File or path name too long",
  37: "No record locks available",
  38: "Function not implemented",
  39: "Directory not empty",
  40: "Too many symbolic links",
  42: "No message of desired type",
  43: "Identifier removed",
  44: "Channel number out of range",
  45: "Level 2 not synchronized",
  46: "Level 3 halted",
  47: "Level 3 reset",
  48: "Link number out of range",
  49: "Protocol driver not attached",
  50: "No CSI structure available",
  51: "Level 2 halted",
  52: "Invalid exchange",
  53: "Invalid request descriptor",
  54: "Exchange full",
  55: "No anode",
  56: "Invalid request code",
  57: "Invalid slot",
  59: "Bad font file fmt",
  60: "Device not a stream",
  61: "No data (for no delay io)",
  62: "Timer expired",
  63: "Out of streams resources",
  64: "Machine is not on the network",
  65: "Package not installed",
  66: "The object is remote",
  67: "The link has been severed",
  68: "Advertise error",
  69: "Srmount error",
  70: "Communication error on send",
  71: "Protocol error",
  72: "Multihop attempted",
  73: "Cross mount point (not really error)",
  74: "Trying to read unreadable message",
  75: "Value too large for defined data type",
  76: "Given log. name not unique",
  77: "f.d. invalid for this operation",
  78: "Remote address changed",
  79: "Can   access a needed shared lib",
  80: "Accessing a corrupted shared lib",
  81: ".lib section in a.out corrupted",
  82: "Attempting to link in too many libs",
  83: "Attempting to exec a shared library",
  84: "Illegal byte sequence",
  86: "Streams pipe error",
  87: "Too many users",
  88: "Socket operation on non-socket",
  89: "Destination address required",
  90: "Message too long",
  91: "Protocol wrong type for socket",
  92: "Protocol not available",
  93: "Unknown protocol",
  94: "Socket type not supported",
  95: "Not supported",
  96: "Protocol family not supported",
  97: "Address family not supported by protocol family",
  98: "Address already in use",
  99: "Address not available",
  100: "Network interface is not configured",
  101: "Network is unreachable",
  102: "Connection reset by network",
  103: "Connection aborted",
  104: "Connection reset by peer",
  105: "No buffer space available",
  106: "Socket is already connected",
  107: "Socket is not connected",
  108: "Can't send after socket shutdown",
  109: "Too many references",
  110: "Connection timed out",
  111: "Connection refused",
  112: "Host is down",
  113: "Host is unreachable",
  114: "Socket already connected",
  115: "Connection already in progress",
  116: "Stale file handle",
  122: "Quota exceeded",
  123: "No medium (in tape drive)",
  125: "Operation canceled",
  130: "Previous owner died",
  131: "State not recoverable",
};
var TTY = {
  ttys: [],
  init: function () {},
  shutdown: function () {},
  register: function (dev, ops) {
    TTY.ttys[dev] = { input: [], output: [], ops: ops };
    FS.registerDevice(dev, TTY.stream_ops);
  },
  stream_ops: {
    open: function (stream) {
      var tty = TTY.ttys[stream.node.rdev];
      if (!tty) {
        throw new FS.ErrnoError(ERRNO_CODES.ENODEV);
      }
      stream.tty = tty;
      stream.seekable = false;
    },
    close: function (stream) {
      stream.tty.ops.flush(stream.tty);
    },
    flush: function (stream) {
      stream.tty.ops.flush(stream.tty);
    },
    read: function (stream, buffer, offset, length, pos) {
      if (!stream.tty || !stream.tty.ops.get_char) {
        throw new FS.ErrnoError(ERRNO_CODES.ENXIO);
      }
      var bytesRead = 0;
      for (var i = 0; i < length; i++) {
        var result;
        try {
          result = stream.tty.ops.get_char(stream.tty);
        } catch (e) {
          throw new FS.ErrnoError(ERRNO_CODES.EIO);
        }
        if (result === undefined && bytesRead === 0) {
          throw new FS.ErrnoError(ERRNO_CODES.EAGAIN);
        }
        if (result === null || result === undefined) break;
        bytesRead++;
        buffer[offset + i] = result;
      }
      if (bytesRead) {
        stream.node.timestamp = Date.now();
      }
      return bytesRead;
    },
    write: function (stream, buffer, offset, length, pos) {
      if (!stream.tty || !stream.tty.ops.put_char) {
        throw new FS.ErrnoError(ERRNO_CODES.ENXIO);
      }
      for (var i = 0; i < length; i++) {
        try {
          stream.tty.ops.put_char(stream.tty, buffer[offset + i]);
        } catch (e) {
          throw new FS.ErrnoError(ERRNO_CODES.EIO);
        }
      }
      if (length) {
        stream.node.timestamp = Date.now();
      }
      return i;
    },
  },
  default_tty_ops: {
    get_char: function (tty) {
      if (!tty.input.length) {
        var result = null;
        if (ENVIRONMENT_IS_NODE) {
          result = process["stdin"]["read"]();
          if (!result) {
            if (
              process["stdin"]["_readableState"] &&
              process["stdin"]["_readableState"]["ended"]
            ) {
              return null;
            }
            return undefined;
          }
        } else if (
          typeof window != "undefined" &&
          typeof window.prompt == "function"
        ) {
          result = window.prompt("Input: ");
          if (result !== null) {
            result += "\n";
          }
        } else if (typeof readline == "function") {
          result = readline();
          if (result !== null) {
            result += "\n";
          }
        }
        if (!result) {
          return null;
        }
        tty.input = intArrayFromString(result, true);
      }
      return tty.input.shift();
    },
    flush: function (tty) {
      if (tty.output && tty.output.length > 0) {
        Module["print"](tty.output.join(""));
        tty.output = [];
      }
    },
    put_char: function (tty, val) {
      if (val === null || val === 10) {
        Module["print"](tty.output.join(""));
        tty.output = [];
      } else {
        tty.output.push(TTY.utf8.processCChar(val));
      }
    },
  },
  default_tty1_ops: {
    put_char: function (tty, val) {
      if (val === null || val === 10) {
        Module["printErr"](tty.output.join(""));
        tty.output = [];
      } else {
        tty.output.push(TTY.utf8.processCChar(val));
      }
    },
    flush: function (tty) {
      if (tty.output && tty.output.length > 0) {
        Module["printErr"](tty.output.join(""));
        tty.output = [];
      }
    },
  },
};
var MEMFS = {
  ops_table: null,
  mount: function (mount) {
    return MEMFS.createNode(null, "/", 16384 | 511, 0);
  },
  createNode: function (parent, name, mode, dev) {
    if (FS.isBlkdev(mode) || FS.isFIFO(mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    if (!MEMFS.ops_table) {
      MEMFS.ops_table = {
        dir: {
          node: {
            getattr: MEMFS.node_ops.getattr,
            setattr: MEMFS.node_ops.setattr,
            lookup: MEMFS.node_ops.lookup,
            mknod: MEMFS.node_ops.mknod,
            rename: MEMFS.node_ops.rename,
            unlink: MEMFS.node_ops.unlink,
            rmdir: MEMFS.node_ops.rmdir,
            readdir: MEMFS.node_ops.readdir,
            symlink: MEMFS.node_ops.symlink,
          },
          stream: { llseek: MEMFS.stream_ops.llseek },
        },
        file: {
          node: {
            getattr: MEMFS.node_ops.getattr,
            setattr: MEMFS.node_ops.setattr,
          },
          stream: {
            llseek: MEMFS.stream_ops.llseek,
            read: MEMFS.stream_ops.read,
            write: MEMFS.stream_ops.write,
            allocate: MEMFS.stream_ops.allocate,
            mmap: MEMFS.stream_ops.mmap,
          },
        },
        link: {
          node: {
            getattr: MEMFS.node_ops.getattr,
            setattr: MEMFS.node_ops.setattr,
            readlink: MEMFS.node_ops.readlink,
          },
          stream: {},
        },
        chrdev: {
          node: {
            getattr: MEMFS.node_ops.getattr,
            setattr: MEMFS.node_ops.setattr,
          },
          stream: FS.chrdev_stream_ops,
        },
      };
    }
    var node = FS.createNode(parent, name, mode, dev);
    if (FS.isDir(node.mode)) {
      node.node_ops = MEMFS.ops_table.dir.node;
      node.stream_ops = MEMFS.ops_table.dir.stream;
      node.contents = {};
    } else if (FS.isFile(node.mode)) {
      node.node_ops = MEMFS.ops_table.file.node;
      node.stream_ops = MEMFS.ops_table.file.stream;
      node.usedBytes = 0;
      node.contents = null;
    } else if (FS.isLink(node.mode)) {
      node.node_ops = MEMFS.ops_table.link.node;
      node.stream_ops = MEMFS.ops_table.link.stream;
    } else if (FS.isChrdev(node.mode)) {
      node.node_ops = MEMFS.ops_table.chrdev.node;
      node.stream_ops = MEMFS.ops_table.chrdev.stream;
    }
    node.timestamp = Date.now();
    if (parent) {
      parent.contents[name] = node;
    }
    return node;
  },
  getFileDataAsRegularArray: function (node) {
    if (node.contents && node.contents.subarray) {
      var arr = [];
      for (var i = 0; i < node.usedBytes; ++i) arr.push(node.contents[i]);
      return arr;
    }
    return node.contents;
  },
  getFileDataAsTypedArray: function (node) {
    if (!node.contents) return new Uint8Array();
    if (node.contents.subarray)
      return node.contents.subarray(0, node.usedBytes);
    return new Uint8Array(node.contents);
  },
  expandFileStorage: function (node, newCapacity) {
    if (
      node.contents &&
      node.contents.subarray &&
      newCapacity > node.contents.length
    ) {
      node.contents = MEMFS.getFileDataAsRegularArray(node);
      node.usedBytes = node.contents.length;
    }
    if (!node.contents || node.contents.subarray) {
      var prevCapacity = node.contents ? node.contents.buffer.byteLength : 0;
      if (prevCapacity >= newCapacity) return;
      var CAPACITY_DOUBLING_MAX = 1024 * 1024;
      newCapacity = Math.max(
        newCapacity,
        (prevCapacity * (prevCapacity < CAPACITY_DOUBLING_MAX ? 2 : 1.125)) | 0
      );
      if (prevCapacity != 0) newCapacity = Math.max(newCapacity, 256);
      var oldContents = node.contents;
      node.contents = new Uint8Array(newCapacity);
      if (node.usedBytes > 0)
        node.contents.set(oldContents.subarray(0, node.usedBytes), 0);
      return;
    }
    if (!node.contents && newCapacity > 0) node.contents = [];
    while (node.contents.length < newCapacity) node.contents.push(0);
  },
  resizeFileStorage: function (node, newSize) {
    if (node.usedBytes == newSize) return;
    if (newSize == 0) {
      node.contents = null;
      node.usedBytes = 0;
      return;
    }
    if (!node.contents || node.contents.subarray) {
      var oldContents = node.contents;
      node.contents = new Uint8Array(new ArrayBuffer(newSize));
      if (oldContents) {
        node.contents.set(
          oldContents.subarray(0, Math.min(newSize, node.usedBytes))
        );
      }
      node.usedBytes = newSize;
      return;
    }
    if (!node.contents) node.contents = [];
    if (node.contents.length > newSize) node.contents.length = newSize;
    else while (node.contents.length < newSize) node.contents.push(0);
    node.usedBytes = newSize;
  },
  node_ops: {
    getattr: function (node) {
      var attr = {};
      attr.dev = FS.isChrdev(node.mode) ? node.id : 1;
      attr.ino = node.id;
      attr.mode = node.mode;
      attr.nlink = 1;
      attr.uid = 0;
      attr.gid = 0;
      attr.rdev = node.rdev;
      if (FS.isDir(node.mode)) {
        attr.size = 4096;
      } else if (FS.isFile(node.mode)) {
        attr.size = node.usedBytes;
      } else if (FS.isLink(node.mode)) {
        attr.size = node.link.length;
      } else {
        attr.size = 0;
      }
      attr.atime = new Date(node.timestamp);
      attr.mtime = new Date(node.timestamp);
      attr.ctime = new Date(node.timestamp);
      attr.blksize = 4096;
      attr.blocks = Math.ceil(attr.size / attr.blksize);
      return attr;
    },
    setattr: function (node, attr) {
      if (attr.mode !== undefined) {
        node.mode = attr.mode;
      }
      if (attr.timestamp !== undefined) {
        node.timestamp = attr.timestamp;
      }
      if (attr.size !== undefined) {
        MEMFS.resizeFileStorage(node, attr.size);
      }
    },
    lookup: function (parent, name) {
      throw FS.genericErrors[ERRNO_CODES.ENOENT];
    },
    mknod: function (parent, name, mode, dev) {
      return MEMFS.createNode(parent, name, mode, dev);
    },
    rename: function (old_node, new_dir, new_name) {
      if (FS.isDir(old_node.mode)) {
        var new_node;
        try {
          new_node = FS.lookupNode(new_dir, new_name);
        } catch (e) {}
        if (new_node) {
          for (var i in new_node.contents) {
            throw new FS.ErrnoError(ERRNO_CODES.ENOTEMPTY);
          }
        }
      }
      delete old_node.parent.contents[old_node.name];
      old_node.name = new_name;
      new_dir.contents[new_name] = old_node;
      old_node.parent = new_dir;
    },
    unlink: function (parent, name) {
      delete parent.contents[name];
    },
    rmdir: function (parent, name) {
      var node = FS.lookupNode(parent, name);
      for (var i in node.contents) {
        throw new FS.ErrnoError(ERRNO_CODES.ENOTEMPTY);
      }
      delete parent.contents[name];
    },
    readdir: function (node) {
      var entries = [".", ".."];
      for (var key in node.contents) {
        if (!node.contents.hasOwnProperty(key)) {
          continue;
        }
        entries.push(key);
      }
      return entries;
    },
    symlink: function (parent, newname, oldpath) {
      var node = MEMFS.createNode(parent, newname, 511 | 40960, 0);
      node.link = oldpath;
      return node;
    },
    readlink: function (node) {
      if (!FS.isLink(node.mode)) {
        throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
      }
      return node.link;
    },
  },
  stream_ops: {
    read: function (stream, buffer, offset, length, position) {
      var contents = stream.node.contents;
      if (position >= stream.node.usedBytes) return 0;
      var size = Math.min(stream.node.usedBytes - position, length);
      assert(size >= 0);
      if (size > 8 && contents.subarray) {
        buffer.set(contents.subarray(position, position + size), offset);
      } else {
        for (var i = 0; i < size; i++)
          buffer[offset + i] = contents[position + i];
      }
      return size;
    },
    write: function (stream, buffer, offset, length, position, canOwn) {
      if (!length) return 0;
      var node = stream.node;
      node.timestamp = Date.now();
      if (buffer.subarray && (!node.contents || node.contents.subarray)) {
        if (canOwn) {
          node.contents = buffer.subarray(offset, offset + length);
          node.usedBytes = length;
          return length;
        } else if (node.usedBytes === 0 && position === 0) {
          node.contents = new Uint8Array(
            buffer.subarray(offset, offset + length)
          );
          node.usedBytes = length;
          return length;
        } else if (position + length <= node.usedBytes) {
          node.contents.set(buffer.subarray(offset, offset + length), position);
          return length;
        }
      }
      MEMFS.expandFileStorage(node, position + length);
      if (node.contents.subarray && buffer.subarray)
        node.contents.set(buffer.subarray(offset, offset + length), position);
      else
        for (var i = 0; i < length; i++) {
          node.contents[position + i] = buffer[offset + i];
        }
      node.usedBytes = Math.max(node.usedBytes, position + length);
      return length;
    },
    llseek: function (stream, offset, whence) {
      var position = offset;
      if (whence === 1) {
        position += stream.position;
      } else if (whence === 2) {
        if (FS.isFile(stream.node.mode)) {
          position += stream.node.usedBytes;
        }
      }
      if (position < 0) {
        throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
      }
      return position;
    },
    allocate: function (stream, offset, length) {
      MEMFS.expandFileStorage(stream.node, offset + length);
      stream.node.usedBytes = Math.max(stream.node.usedBytes, offset + length);
    },
    mmap: function (stream, buffer, offset, length, position, prot, flags) {
      if (!FS.isFile(stream.node.mode)) {
        throw new FS.ErrnoError(ERRNO_CODES.ENODEV);
      }
      var ptr;
      var allocated;
      var contents = stream.node.contents;
      if (
        !(flags & 2) &&
        (contents.buffer === buffer || contents.buffer === buffer.buffer)
      ) {
        allocated = false;
        ptr = contents.byteOffset;
      } else {
        if (position > 0 || position + length < stream.node.usedBytes) {
          if (contents.subarray) {
            contents = contents.subarray(position, position + length);
          } else {
            contents = Array.prototype.slice.call(
              contents,
              position,
              position + length
            );
          }
        }
        allocated = true;
        ptr = _malloc(length);
        if (!ptr) {
          throw new FS.ErrnoError(ERRNO_CODES.ENOMEM);
        }
        buffer.set(contents, ptr);
      }
      return { ptr: ptr, allocated: allocated };
    },
  },
};
var IDBFS = {
  dbs: {},
  indexedDB: function () {
    if (typeof indexedDB !== "undefined") return indexedDB;
    var ret = null;
    if (typeof window === "object")
      ret =
        window.indexedDB ||
        window.mozIndexedDB ||
        window.webkitIndexedDB ||
        window.msIndexedDB;
    assert(ret, "IDBFS used, but indexedDB not supported");
    return ret;
  },
  DB_VERSION: 21,
  DB_STORE_NAME: "FILE_DATA",
  mount: function (mount) {
    return MEMFS.mount.apply(null, arguments);
  },
  syncfs: function (mount, populate, callback) {
    IDBFS.getLocalSet(mount, function (err, local) {
      if (err) return callback(err);
      IDBFS.getRemoteSet(mount, function (err, remote) {
        if (err) return callback(err);
        var src = populate ? remote : local;
        var dst = populate ? local : remote;
        IDBFS.reconcile(src, dst, callback);
      });
    });
  },
  getDB: function (name, callback) {
    var db = IDBFS.dbs[name];
    if (db) {
      return callback(null, db);
    }
    var req;
    try {
      req = IDBFS.indexedDB().open(name, IDBFS.DB_VERSION);
    } catch (e) {
      return callback(e);
    }
    req.onupgradeneeded = function (e) {
      var db = e.target.result;
      var transaction = e.target.transaction;
      var fileStore;
      if (db.objectStoreNames.contains(IDBFS.DB_STORE_NAME)) {
        fileStore = transaction.objectStore(IDBFS.DB_STORE_NAME);
      } else {
        fileStore = db.createObjectStore(IDBFS.DB_STORE_NAME);
      }
      fileStore.createIndex("timestamp", "timestamp", { unique: false });
    };
    req.onsuccess = function () {
      db = req.result;
      IDBFS.dbs[name] = db;
      callback(null, db);
    };
    req.onerror = function () {
      callback(this.error);
    };
  },
  getLocalSet: function (mount, callback) {
    var entries = {};
    function isRealDir(p) {
      return p !== "." && p !== "..";
    }
    function toAbsolute(root) {
      return function (p) {
        return PATH.join2(root, p);
      };
    }
    var check = FS.readdir(mount.mountpoint)
      .filter(isRealDir)
      .map(toAbsolute(mount.mountpoint));
    while (check.length) {
      var path = check.pop();
      var stat;
      try {
        stat = FS.stat(path);
      } catch (e) {
        return callback(e);
      }
      if (FS.isDir(stat.mode)) {
        check.push.apply(
          check,
          FS.readdir(path).filter(isRealDir).map(toAbsolute(path))
        );
      }
      entries[path] = { timestamp: stat.mtime };
    }
    return callback(null, { type: "local", entries: entries });
  },
  getRemoteSet: function (mount, callback) {
    var entries = {};
    IDBFS.getDB(mount.mountpoint, function (err, db) {
      if (err) return callback(err);
      var transaction = db.transaction([IDBFS.DB_STORE_NAME], "readonly");
      transaction.onerror = function () {
        callback(this.error);
      };
      var store = transaction.objectStore(IDBFS.DB_STORE_NAME);
      var index = store.index("timestamp");
      index.openKeyCursor().onsuccess = function (event) {
        var cursor = event.target.result;
        if (!cursor) {
          return callback(null, { type: "remote", db: db, entries: entries });
        }
        entries[cursor.primaryKey] = { timestamp: cursor.key };
        cursor.continue();
      };
    });
  },
  loadLocalEntry: function (path, callback) {
    var stat, node;
    try {
      var lookup = FS.lookupPath(path);
      node = lookup.node;
      stat = FS.stat(path);
    } catch (e) {
      return callback(e);
    }
    if (FS.isDir(stat.mode)) {
      return callback(null, { timestamp: stat.mtime, mode: stat.mode });
    } else if (FS.isFile(stat.mode)) {
      node.contents = MEMFS.getFileDataAsTypedArray(node);
      return callback(null, {
        timestamp: stat.mtime,
        mode: stat.mode,
        contents: node.contents,
      });
    } else {
      return callback(new Error("node type not supported"));
    }
  },
  storeLocalEntry: function (path, entry, callback) {
    try {
      if (FS.isDir(entry.mode)) {
        FS.mkdir(path, entry.mode);
      } else if (FS.isFile(entry.mode)) {
        FS.writeFile(path, entry.contents, {
          encoding: "binary",
          canOwn: true,
        });
      } else {
        return callback(new Error("node type not supported"));
      }
      FS.chmod(path, entry.mode);
      FS.utime(path, entry.timestamp, entry.timestamp);
    } catch (e) {
      return callback(e);
    }
    callback(null);
  },
  removeLocalEntry: function (path, callback) {
    try {
      var lookup = FS.lookupPath(path);
      var stat = FS.stat(path);
      if (FS.isDir(stat.mode)) {
        FS.rmdir(path);
      } else if (FS.isFile(stat.mode)) {
        FS.unlink(path);
      }
    } catch (e) {
      return callback(e);
    }
    callback(null);
  },
  loadRemoteEntry: function (store, path, callback) {
    var req = store.get(path);
    req.onsuccess = function (event) {
      callback(null, event.target.result);
    };
    req.onerror = function () {
      callback(this.error);
    };
  },
  storeRemoteEntry: function (store, path, entry, callback) {
    var req = store.put(entry, path);
    req.onsuccess = function () {
      callback(null);
    };
    req.onerror = function () {
      callback(this.error);
    };
  },
  removeRemoteEntry: function (store, path, callback) {
    var req = store.delete(path);
    req.onsuccess = function () {
      callback(null);
    };
    req.onerror = function () {
      callback(this.error);
    };
  },
  reconcile: function (src, dst, callback) {
    var total = 0;
    var create = [];
    Object.keys(src.entries).forEach(function (key) {
      var e = src.entries[key];
      var e2 = dst.entries[key];
      if (!e2 || e.timestamp > e2.timestamp) {
        create.push(key);
        total++;
      }
    });
    var remove = [];
    Object.keys(dst.entries).forEach(function (key) {
      var e = dst.entries[key];
      var e2 = src.entries[key];
      if (!e2) {
        remove.push(key);
        total++;
      }
    });
    if (!total) {
      return callback(null);
    }
    var errored = false;
    var completed = 0;
    var db = src.type === "remote" ? src.db : dst.db;
    var transaction = db.transaction([IDBFS.DB_STORE_NAME], "readwrite");
    var store = transaction.objectStore(IDBFS.DB_STORE_NAME);
    function done(err) {
      if (err) {
        if (!done.errored) {
          done.errored = true;
          return callback(err);
        }
        return;
      }
      if (++completed >= total) {
        return callback(null);
      }
    }
    transaction.onerror = function () {
      done(this.error);
    };
    create.sort().forEach(function (path) {
      if (dst.type === "local") {
        IDBFS.loadRemoteEntry(store, path, function (err, entry) {
          if (err) return done(err);
          IDBFS.storeLocalEntry(path, entry, done);
        });
      } else {
        IDBFS.loadLocalEntry(path, function (err, entry) {
          if (err) return done(err);
          IDBFS.storeRemoteEntry(store, path, entry, done);
        });
      }
    });
    remove
      .sort()
      .reverse()
      .forEach(function (path) {
        if (dst.type === "local") {
          IDBFS.removeLocalEntry(path, done);
        } else {
          IDBFS.removeRemoteEntry(store, path, done);
        }
      });
  },
};
var NODEFS = {
  isWindows: false,
  staticInit: function () {
    NODEFS.isWindows = !!process.platform.match(/^win/);
  },
  mount: function (mount) {
    assert(ENVIRONMENT_IS_NODE);
    return NODEFS.createNode(null, "/", NODEFS.getMode(mount.opts.root), 0);
  },
  createNode: function (parent, name, mode, dev) {
    if (!FS.isDir(mode) && !FS.isFile(mode) && !FS.isLink(mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    var node = FS.createNode(parent, name, mode);
    node.node_ops = NODEFS.node_ops;
    node.stream_ops = NODEFS.stream_ops;
    return node;
  },
  getMode: function (path) {
    var stat;
    try {
      stat = fs.lstatSync(path);
      if (NODEFS.isWindows) {
        stat.mode = stat.mode | ((stat.mode & 146) >> 1);
      }
    } catch (e) {
      if (!e.code) throw e;
      throw new FS.ErrnoError(ERRNO_CODES[e.code]);
    }
    return stat.mode;
  },
  realPath: function (node) {
    var parts = [];
    while (node.parent !== node) {
      parts.push(node.name);
      node = node.parent;
    }
    parts.push(node.mount.opts.root);
    parts.reverse();
    return PATH.join.apply(null, parts);
  },
  flagsToPermissionStringMap: {
    0: "r",
    1: "r+",
    2: "r+",
    64: "r",
    65: "r+",
    66: "r+",
    129: "rx+",
    193: "rx+",
    514: "w+",
    577: "w",
    578: "w+",
    705: "wx",
    706: "wx+",
    1024: "a",
    1025: "a",
    1026: "a+",
    1089: "a",
    1090: "a+",
    1153: "ax",
    1154: "ax+",
    1217: "ax",
    1218: "ax+",
    4096: "rs",
    4098: "rs+",
  },
  flagsToPermissionString: function (flags) {
    if (flags in NODEFS.flagsToPermissionStringMap) {
      return NODEFS.flagsToPermissionStringMap[flags];
    } else {
      return flags;
    }
  },
  node_ops: {
    getattr: function (node) {
      var path = NODEFS.realPath(node);
      var stat;
      try {
        stat = fs.lstatSync(path);
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
      if (NODEFS.isWindows && !stat.blksize) {
        stat.blksize = 4096;
      }
      if (NODEFS.isWindows && !stat.blocks) {
        stat.blocks = ((stat.size + stat.blksize - 1) / stat.blksize) | 0;
      }
      return {
        dev: stat.dev,
        ino: stat.ino,
        mode: stat.mode,
        nlink: stat.nlink,
        uid: stat.uid,
        gid: stat.gid,
        rdev: stat.rdev,
        size: stat.size,
        atime: stat.atime,
        mtime: stat.mtime,
        ctime: stat.ctime,
        blksize: stat.blksize,
        blocks: stat.blocks,
      };
    },
    setattr: function (node, attr) {
      var path = NODEFS.realPath(node);
      try {
        if (attr.mode !== undefined) {
          fs.chmodSync(path, attr.mode);
          node.mode = attr.mode;
        }
        if (attr.timestamp !== undefined) {
          var date = new Date(attr.timestamp);
          fs.utimesSync(path, date, date);
        }
        if (attr.size !== undefined) {
          fs.truncateSync(path, attr.size);
        }
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    lookup: function (parent, name) {
      var path = PATH.join2(NODEFS.realPath(parent), name);
      var mode = NODEFS.getMode(path);
      return NODEFS.createNode(parent, name, mode);
    },
    mknod: function (parent, name, mode, dev) {
      var node = NODEFS.createNode(parent, name, mode, dev);
      var path = NODEFS.realPath(node);
      try {
        if (FS.isDir(node.mode)) {
          fs.mkdirSync(path, node.mode);
        } else {
          fs.writeFileSync(path, "", { mode: node.mode });
        }
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
      return node;
    },
    rename: function (oldNode, newDir, newName) {
      var oldPath = NODEFS.realPath(oldNode);
      var newPath = PATH.join2(NODEFS.realPath(newDir), newName);
      try {
        fs.renameSync(oldPath, newPath);
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    unlink: function (parent, name) {
      var path = PATH.join2(NODEFS.realPath(parent), name);
      try {
        fs.unlinkSync(path);
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    rmdir: function (parent, name) {
      var path = PATH.join2(NODEFS.realPath(parent), name);
      try {
        fs.rmdirSync(path);
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    readdir: function (node) {
      var path = NODEFS.realPath(node);
      try {
        return fs.readdirSync(path);
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    symlink: function (parent, newName, oldPath) {
      var newPath = PATH.join2(NODEFS.realPath(parent), newName);
      try {
        fs.symlinkSync(oldPath, newPath);
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    readlink: function (node) {
      var path = NODEFS.realPath(node);
      try {
        return fs.readlinkSync(path);
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
  },
  stream_ops: {
    open: function (stream) {
      var path = NODEFS.realPath(stream.node);
      try {
        if (FS.isFile(stream.node.mode)) {
          stream.nfd = fs.openSync(
            path,
            NODEFS.flagsToPermissionString(stream.flags)
          );
        }
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    close: function (stream) {
      try {
        if (FS.isFile(stream.node.mode) && stream.nfd) {
          fs.closeSync(stream.nfd);
        }
      } catch (e) {
        if (!e.code) throw e;
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
    },
    read: function (stream, buffer, offset, length, position) {
      if (length === 0) return 0;
      var nbuffer = new Buffer(length);
      var res;
      try {
        res = fs.readSync(stream.nfd, nbuffer, 0, length, position);
      } catch (e) {
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
      if (res > 0) {
        for (var i = 0; i < res; i++) {
          buffer[offset + i] = nbuffer[i];
        }
      }
      return res;
    },
    write: function (stream, buffer, offset, length, position) {
      var nbuffer = new Buffer(buffer.subarray(offset, offset + length));
      var res;
      try {
        res = fs.writeSync(stream.nfd, nbuffer, 0, length, position);
      } catch (e) {
        throw new FS.ErrnoError(ERRNO_CODES[e.code]);
      }
      return res;
    },
    llseek: function (stream, offset, whence) {
      var position = offset;
      if (whence === 1) {
        position += stream.position;
      } else if (whence === 2) {
        if (FS.isFile(stream.node.mode)) {
          try {
            var stat = fs.fstatSync(stream.nfd);
            position += stat.size;
          } catch (e) {
            throw new FS.ErrnoError(ERRNO_CODES[e.code]);
          }
        }
      }
      if (position < 0) {
        throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
      }
      return position;
    },
  },
};
var _stdin = allocate(1, "i32*", ALLOC_STATIC);
var _stdout = allocate(1, "i32*", ALLOC_STATIC);
var _stderr = allocate(1, "i32*", ALLOC_STATIC);
function _fflush(stream) {}
var FS = {
  root: null,
  mounts: [],
  devices: [null],
  streams: [],
  nextInode: 1,
  nameTable: null,
  currentPath: "/",
  initialized: false,
  ignorePermissions: true,
  trackingDelegate: {},
  tracking: { openFlags: { READ: 1, WRITE: 2 } },
  ErrnoError: null,
  genericErrors: {},
  handleFSError: function (e) {
    if (!(e instanceof FS.ErrnoError)) throw e + " : " + stackTrace();
    return ___setErrNo(e.errno);
  },
  lookupPath: function (path, opts) {
    path = PATH.resolve(FS.cwd(), path);
    opts = opts || {};
    if (!path) return { path: "", node: null };
    var defaults = { follow_mount: true, recurse_count: 0 };
    for (var key in defaults) {
      if (opts[key] === undefined) {
        opts[key] = defaults[key];
      }
    }
    if (opts.recurse_count > 8) {
      throw new FS.ErrnoError(ERRNO_CODES.ELOOP);
    }
    var parts = PATH.normalizeArray(
      path.split("/").filter(function (p) {
        return !!p;
      }),
      false
    );
    var current = FS.root;
    var current_path = "/";
    for (var i = 0; i < parts.length; i++) {
      var islast = i === parts.length - 1;
      if (islast && opts.parent) {
        break;
      }
      current = FS.lookupNode(current, parts[i]);
      current_path = PATH.join2(current_path, parts[i]);
      if (FS.isMountpoint(current)) {
        if (!islast || (islast && opts.follow_mount)) {
          current = current.mounted.root;
        }
      }
      if (!islast || opts.follow) {
        var count = 0;
        while (FS.isLink(current.mode)) {
          var link = FS.readlink(current_path);
          current_path = PATH.resolve(PATH.dirname(current_path), link);
          var lookup = FS.lookupPath(current_path, {
            recurse_count: opts.recurse_count,
          });
          current = lookup.node;
          if (count++ > 40) {
            throw new FS.ErrnoError(ERRNO_CODES.ELOOP);
          }
        }
      }
    }
    return { path: current_path, node: current };
  },
  getPath: function (node) {
    var path;
    while (true) {
      if (FS.isRoot(node)) {
        var mount = node.mount.mountpoint;
        if (!path) return mount;
        return mount[mount.length - 1] !== "/"
          ? mount + "/" + path
          : mount + path;
      }
      path = path ? node.name + "/" + path : node.name;
      node = node.parent;
    }
  },
  hashName: function (parentid, name) {
    var hash = 0;
    for (var i = 0; i < name.length; i++) {
      hash = ((hash << 5) - hash + name.charCodeAt(i)) | 0;
    }
    return ((parentid + hash) >>> 0) % FS.nameTable.length;
  },
  hashAddNode: function (node) {
    var hash = FS.hashName(node.parent.id, node.name);
    node.name_next = FS.nameTable[hash];
    FS.nameTable[hash] = node;
  },
  hashRemoveNode: function (node) {
    var hash = FS.hashName(node.parent.id, node.name);
    if (FS.nameTable[hash] === node) {
      FS.nameTable[hash] = node.name_next;
    } else {
      var current = FS.nameTable[hash];
      while (current) {
        if (current.name_next === node) {
          current.name_next = node.name_next;
          break;
        }
        current = current.name_next;
      }
    }
  },
  lookupNode: function (parent, name) {
    var err = FS.mayLookup(parent);
    if (err) {
      throw new FS.ErrnoError(err, parent);
    }
    var hash = FS.hashName(parent.id, name);
    for (var node = FS.nameTable[hash]; node; node = node.name_next) {
      var nodeName = node.name;
      if (node.parent.id === parent.id && nodeName === name) {
        return node;
      }
    }
    return FS.lookup(parent, name);
  },
  createNode: function (parent, name, mode, rdev) {
    if (!FS.FSNode) {
      FS.FSNode = function (parent, name, mode, rdev) {
        if (!parent) {
          parent = this;
        }
        this.parent = parent;
        this.mount = parent.mount;
        this.mounted = null;
        this.id = FS.nextInode++;
        this.name = name;
        this.mode = mode;
        this.node_ops = {};
        this.stream_ops = {};
        this.rdev = rdev;
      };
      FS.FSNode.prototype = {};
      var readMode = 292 | 73;
      var writeMode = 146;
      Object.defineProperties(FS.FSNode.prototype, {
        read: {
          get: function () {
            return (this.mode & readMode) === readMode;
          },
          set: function (val) {
            val ? (this.mode |= readMode) : (this.mode &= ~readMode);
          },
        },
        write: {
          get: function () {
            return (this.mode & writeMode) === writeMode;
          },
          set: function (val) {
            val ? (this.mode |= writeMode) : (this.mode &= ~writeMode);
          },
        },
        isFolder: {
          get: function () {
            return FS.isDir(this.mode);
          },
        },
        isDevice: {
          get: function () {
            return FS.isChrdev(this.mode);
          },
        },
      });
    }
    var node = new FS.FSNode(parent, name, mode, rdev);
    FS.hashAddNode(node);
    return node;
  },
  destroyNode: function (node) {
    FS.hashRemoveNode(node);
  },
  isRoot: function (node) {
    return node === node.parent;
  },
  isMountpoint: function (node) {
    return !!node.mounted;
  },
  isFile: function (mode) {
    return (mode & 61440) === 32768;
  },
  isDir: function (mode) {
    return (mode & 61440) === 16384;
  },
  isLink: function (mode) {
    return (mode & 61440) === 40960;
  },
  isChrdev: function (mode) {
    return (mode & 61440) === 8192;
  },
  isBlkdev: function (mode) {
    return (mode & 61440) === 24576;
  },
  isFIFO: function (mode) {
    return (mode & 61440) === 4096;
  },
  isSocket: function (mode) {
    return (mode & 49152) === 49152;
  },
  flagModes: {
    r: 0,
    rs: 1052672,
    "r+": 2,
    w: 577,
    wx: 705,
    xw: 705,
    "w+": 578,
    "wx+": 706,
    "xw+": 706,
    a: 1089,
    ax: 1217,
    xa: 1217,
    "a+": 1090,
    "ax+": 1218,
    "xa+": 1218,
  },
  modeStringToFlags: function (str) {
    var flags = FS.flagModes[str];
    if (typeof flags === "undefined") {
      throw new Error("Unknown file open mode: " + str);
    }
    return flags;
  },
  flagsToPermissionString: function (flag) {
    var accmode = flag & 2097155;
    var perms = ["r", "w", "rw"][accmode];
    if (flag & 512) {
      perms += "w";
    }
    return perms;
  },
  nodePermissions: function (node, perms) {
    if (FS.ignorePermissions) {
      return 0;
    }
    if (perms.indexOf("r") !== -1 && !(node.mode & 292)) {
      return ERRNO_CODES.EACCES;
    } else if (perms.indexOf("w") !== -1 && !(node.mode & 146)) {
      return ERRNO_CODES.EACCES;
    } else if (perms.indexOf("x") !== -1 && !(node.mode & 73)) {
      return ERRNO_CODES.EACCES;
    }
    return 0;
  },
  mayLookup: function (dir) {
    var err = FS.nodePermissions(dir, "x");
    if (err) return err;
    if (!dir.node_ops.lookup) return ERRNO_CODES.EACCES;
    return 0;
  },
  mayCreate: function (dir, name) {
    try {
      var node = FS.lookupNode(dir, name);
      return ERRNO_CODES.EEXIST;
    } catch (e) {}
    return FS.nodePermissions(dir, "wx");
  },
  mayDelete: function (dir, name, isdir) {
    var node;
    try {
      node = FS.lookupNode(dir, name);
    } catch (e) {
      return e.errno;
    }
    var err = FS.nodePermissions(dir, "wx");
    if (err) {
      return err;
    }
    if (isdir) {
      if (!FS.isDir(node.mode)) {
        return ERRNO_CODES.ENOTDIR;
      }
      if (FS.isRoot(node) || FS.getPath(node) === FS.cwd()) {
        return ERRNO_CODES.EBUSY;
      }
    } else {
      if (FS.isDir(node.mode)) {
        return ERRNO_CODES.EISDIR;
      }
    }
    return 0;
  },
  mayOpen: function (node, flags) {
    if (!node) {
      return ERRNO_CODES.ENOENT;
    }
    if (FS.isLink(node.mode)) {
      return ERRNO_CODES.ELOOP;
    } else if (FS.isDir(node.mode)) {
      if ((flags & 2097155) !== 0 || flags & 512) {
        return ERRNO_CODES.EISDIR;
      }
    }
    return FS.nodePermissions(node, FS.flagsToPermissionString(flags));
  },
  MAX_OPEN_FDS: 4096,
  nextfd: function (fd_start, fd_end) {
    fd_start = fd_start || 0;
    fd_end = fd_end || FS.MAX_OPEN_FDS;
    for (var fd = fd_start; fd <= fd_end; fd++) {
      if (!FS.streams[fd]) {
        return fd;
      }
    }
    throw new FS.ErrnoError(ERRNO_CODES.EMFILE);
  },
  getStream: function (fd) {
    return FS.streams[fd];
  },
  createStream: function (stream, fd_start, fd_end) {
    if (!FS.FSStream) {
      FS.FSStream = function () {};
      FS.FSStream.prototype = {};
      Object.defineProperties(FS.FSStream.prototype, {
        object: {
          get: function () {
            return this.node;
          },
          set: function (val) {
            this.node = val;
          },
        },
        isRead: {
          get: function () {
            return (this.flags & 2097155) !== 1;
          },
        },
        isWrite: {
          get: function () {
            return (this.flags & 2097155) !== 0;
          },
        },
        isAppend: {
          get: function () {
            return this.flags & 1024;
          },
        },
      });
    }
    var newStream = new FS.FSStream();
    for (var p in stream) {
      newStream[p] = stream[p];
    }
    stream = newStream;
    var fd = FS.nextfd(fd_start, fd_end);
    stream.fd = fd;
    FS.streams[fd] = stream;
    return stream;
  },
  closeStream: function (fd) {
    FS.streams[fd] = null;
  },
  getStreamFromPtr: function (ptr) {
    return FS.streams[ptr - 1];
  },
  getPtrForStream: function (stream) {
    return stream ? stream.fd + 1 : 0;
  },
  chrdev_stream_ops: {
    open: function (stream) {
      var device = FS.getDevice(stream.node.rdev);
      stream.stream_ops = device.stream_ops;
      if (stream.stream_ops.open) {
        stream.stream_ops.open(stream);
      }
    },
    llseek: function () {
      throw new FS.ErrnoError(ERRNO_CODES.ESPIPE);
    },
  },
  major: function (dev) {
    return dev >> 8;
  },
  minor: function (dev) {
    return dev & 255;
  },
  makedev: function (ma, mi) {
    return (ma << 8) | mi;
  },
  registerDevice: function (dev, ops) {
    FS.devices[dev] = { stream_ops: ops };
  },
  getDevice: function (dev) {
    return FS.devices[dev];
  },
  getMounts: function (mount) {
    var mounts = [];
    var check = [mount];
    while (check.length) {
      var m = check.pop();
      mounts.push(m);
      check.push.apply(check, m.mounts);
    }
    return mounts;
  },
  syncfs: function (populate, callback) {
    if (typeof populate === "function") {
      callback = populate;
      populate = false;
    }
    var mounts = FS.getMounts(FS.root.mount);
    var completed = 0;
    function done(err) {
      if (err) {
        if (!done.errored) {
          done.errored = true;
          return callback(err);
        }
        return;
      }
      if (++completed >= mounts.length) {
        callback(null);
      }
    }
    mounts.forEach(function (mount) {
      if (!mount.type.syncfs) {
        return done(null);
      }
      mount.type.syncfs(mount, populate, done);
    });
  },
  mount: function (type, opts, mountpoint) {
    var root = mountpoint === "/";
    var pseudo = !mountpoint;
    var node;
    if (root && FS.root) {
      throw new FS.ErrnoError(ERRNO_CODES.EBUSY);
    } else if (!root && !pseudo) {
      var lookup = FS.lookupPath(mountpoint, { follow_mount: false });
      mountpoint = lookup.path;
      node = lookup.node;
      if (FS.isMountpoint(node)) {
        throw new FS.ErrnoError(ERRNO_CODES.EBUSY);
      }
      if (!FS.isDir(node.mode)) {
        throw new FS.ErrnoError(ERRNO_CODES.ENOTDIR);
      }
    }
    var mount = { type: type, opts: opts, mountpoint: mountpoint, mounts: [] };
    var mountRoot = type.mount(mount);
    mountRoot.mount = mount;
    mount.root = mountRoot;
    if (root) {
      FS.root = mountRoot;
    } else if (node) {
      node.mounted = mount;
      if (node.mount) {
        node.mount.mounts.push(mount);
      }
    }
    return mountRoot;
  },
  unmount: function (mountpoint) {
    var lookup = FS.lookupPath(mountpoint, { follow_mount: false });
    if (!FS.isMountpoint(lookup.node)) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    var node = lookup.node;
    var mount = node.mounted;
    var mounts = FS.getMounts(mount);
    Object.keys(FS.nameTable).forEach(function (hash) {
      var current = FS.nameTable[hash];
      while (current) {
        var next = current.name_next;
        if (mounts.indexOf(current.mount) !== -1) {
          FS.destroyNode(current);
        }
        current = next;
      }
    });
    node.mounted = null;
    var idx = node.mount.mounts.indexOf(mount);
    assert(idx !== -1);
    node.mount.mounts.splice(idx, 1);
  },
  lookup: function (parent, name) {
    return parent.node_ops.lookup(parent, name);
  },
  mknod: function (path, mode, dev) {
    var lookup = FS.lookupPath(path, { parent: true });
    var parent = lookup.node;
    var name = PATH.basename(path);
    if (!name || name === "." || name === "..") {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    var err = FS.mayCreate(parent, name);
    if (err) {
      throw new FS.ErrnoError(err);
    }
    if (!parent.node_ops.mknod) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    return parent.node_ops.mknod(parent, name, mode, dev);
  },
  create: function (path, mode) {
    mode = mode !== undefined ? mode : 438;
    mode &= 4095;
    mode |= 32768;
    return FS.mknod(path, mode, 0);
  },
  mkdir: function (path, mode) {
    mode = mode !== undefined ? mode : 511;
    mode &= 511 | 512;
    mode |= 16384;
    return FS.mknod(path, mode, 0);
  },
  mkdev: function (path, mode, dev) {
    if (typeof dev === "undefined") {
      dev = mode;
      mode = 438;
    }
    mode |= 8192;
    return FS.mknod(path, mode, dev);
  },
  symlink: function (oldpath, newpath) {
    if (!PATH.resolve(oldpath)) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOENT);
    }
    var lookup = FS.lookupPath(newpath, { parent: true });
    var parent = lookup.node;
    if (!parent) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOENT);
    }
    var newname = PATH.basename(newpath);
    var err = FS.mayCreate(parent, newname);
    if (err) {
      throw new FS.ErrnoError(err);
    }
    if (!parent.node_ops.symlink) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    return parent.node_ops.symlink(parent, newname, oldpath);
  },
  rename: function (old_path, new_path) {
    var old_dirname = PATH.dirname(old_path);
    var new_dirname = PATH.dirname(new_path);
    var old_name = PATH.basename(old_path);
    var new_name = PATH.basename(new_path);
    var lookup, old_dir, new_dir;
    try {
      lookup = FS.lookupPath(old_path, { parent: true });
      old_dir = lookup.node;
      lookup = FS.lookupPath(new_path, { parent: true });
      new_dir = lookup.node;
    } catch (e) {
      throw new FS.ErrnoError(ERRNO_CODES.EBUSY);
    }
    if (!old_dir || !new_dir) throw new FS.ErrnoError(ERRNO_CODES.ENOENT);
    if (old_dir.mount !== new_dir.mount) {
      throw new FS.ErrnoError(ERRNO_CODES.EXDEV);
    }
    var old_node = FS.lookupNode(old_dir, old_name);
    var relative = PATH.relative(old_path, new_dirname);
    if (relative.charAt(0) !== ".") {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    relative = PATH.relative(new_path, old_dirname);
    if (relative.charAt(0) !== ".") {
      throw new FS.ErrnoError(ERRNO_CODES.ENOTEMPTY);
    }
    var new_node;
    try {
      new_node = FS.lookupNode(new_dir, new_name);
    } catch (e) {}
    if (old_node === new_node) {
      return;
    }
    var isdir = FS.isDir(old_node.mode);
    var err = FS.mayDelete(old_dir, old_name, isdir);
    if (err) {
      throw new FS.ErrnoError(err);
    }
    err = new_node
      ? FS.mayDelete(new_dir, new_name, isdir)
      : FS.mayCreate(new_dir, new_name);
    if (err) {
      throw new FS.ErrnoError(err);
    }
    if (!old_dir.node_ops.rename) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    if (FS.isMountpoint(old_node) || (new_node && FS.isMountpoint(new_node))) {
      throw new FS.ErrnoError(ERRNO_CODES.EBUSY);
    }
    if (new_dir !== old_dir) {
      err = FS.nodePermissions(old_dir, "w");
      if (err) {
        throw new FS.ErrnoError(err);
      }
    }
    try {
      if (FS.trackingDelegate["willMovePath"]) {
        FS.trackingDelegate["willMovePath"](old_path, new_path);
      }
    } catch (e) {
      console.log(
        "FS.trackingDelegate['willMovePath']('" +
          old_path +
          "', '" +
          new_path +
          "') threw an exception: " +
          e.message
      );
    }
    FS.hashRemoveNode(old_node);
    try {
      old_dir.node_ops.rename(old_node, new_dir, new_name);
    } catch (e) {
      throw e;
    } finally {
      FS.hashAddNode(old_node);
    }
    try {
      if (FS.trackingDelegate["onMovePath"])
        FS.trackingDelegate["onMovePath"](old_path, new_path);
    } catch (e) {
      console.log(
        "FS.trackingDelegate['onMovePath']('" +
          old_path +
          "', '" +
          new_path +
          "') threw an exception: " +
          e.message
      );
    }
  },
  rmdir: function (path) {
    var lookup = FS.lookupPath(path, { parent: true });
    var parent = lookup.node;
    var name = PATH.basename(path);
    var node = FS.lookupNode(parent, name);
    var err = FS.mayDelete(parent, name, true);
    if (err) {
      throw new FS.ErrnoError(err);
    }
    if (!parent.node_ops.rmdir) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    if (FS.isMountpoint(node)) {
      throw new FS.ErrnoError(ERRNO_CODES.EBUSY);
    }
    try {
      if (FS.trackingDelegate["willDeletePath"]) {
        FS.trackingDelegate["willDeletePath"](path);
      }
    } catch (e) {
      console.log(
        "FS.trackingDelegate['willDeletePath']('" +
          path +
          "') threw an exception: " +
          e.message
      );
    }
    parent.node_ops.rmdir(parent, name);
    FS.destroyNode(node);
    try {
      if (FS.trackingDelegate["onDeletePath"])
        FS.trackingDelegate["onDeletePath"](path);
    } catch (e) {
      console.log(
        "FS.trackingDelegate['onDeletePath']('" +
          path +
          "') threw an exception: " +
          e.message
      );
    }
  },
  readdir: function (path) {
    var lookup = FS.lookupPath(path, { follow: true });
    var node = lookup.node;
    if (!node.node_ops.readdir) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOTDIR);
    }
    return node.node_ops.readdir(node);
  },
  unlink: function (path) {
    var lookup = FS.lookupPath(path, { parent: true });
    var parent = lookup.node;
    var name = PATH.basename(path);
    var node = FS.lookupNode(parent, name);
    var err = FS.mayDelete(parent, name, false);
    if (err) {
      if (err === ERRNO_CODES.EISDIR) err = ERRNO_CODES.EPERM;
      throw new FS.ErrnoError(err);
    }
    if (!parent.node_ops.unlink) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    if (FS.isMountpoint(node)) {
      throw new FS.ErrnoError(ERRNO_CODES.EBUSY);
    }
    try {
      if (FS.trackingDelegate["willDeletePath"]) {
        FS.trackingDelegate["willDeletePath"](path);
      }
    } catch (e) {
      console.log(
        "FS.trackingDelegate['willDeletePath']('" +
          path +
          "') threw an exception: " +
          e.message
      );
    }
    parent.node_ops.unlink(parent, name);
    FS.destroyNode(node);
    try {
      if (FS.trackingDelegate["onDeletePath"])
        FS.trackingDelegate["onDeletePath"](path);
    } catch (e) {
      console.log(
        "FS.trackingDelegate['onDeletePath']('" +
          path +
          "') threw an exception: " +
          e.message
      );
    }
  },
  readlink: function (path) {
    var lookup = FS.lookupPath(path);
    var link = lookup.node;
    if (!link) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOENT);
    }
    if (!link.node_ops.readlink) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    return link.node_ops.readlink(link);
  },
  stat: function (path, dontFollow) {
    var lookup = FS.lookupPath(path, { follow: !dontFollow });
    var node = lookup.node;
    if (!node) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOENT);
    }
    if (!node.node_ops.getattr) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    return node.node_ops.getattr(node);
  },
  lstat: function (path) {
    return FS.stat(path, true);
  },
  chmod: function (path, mode, dontFollow) {
    var node;
    if (typeof path === "string") {
      var lookup = FS.lookupPath(path, { follow: !dontFollow });
      node = lookup.node;
    } else {
      node = path;
    }
    if (!node.node_ops.setattr) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    node.node_ops.setattr(node, {
      mode: (mode & 4095) | (node.mode & ~4095),
      timestamp: Date.now(),
    });
  },
  lchmod: function (path, mode) {
    FS.chmod(path, mode, true);
  },
  fchmod: function (fd, mode) {
    var stream = FS.getStream(fd);
    if (!stream) {
      throw new FS.ErrnoError(ERRNO_CODES.EBADF);
    }
    FS.chmod(stream.node, mode);
  },
  chown: function (path, uid, gid, dontFollow) {
    var node;
    if (typeof path === "string") {
      var lookup = FS.lookupPath(path, { follow: !dontFollow });
      node = lookup.node;
    } else {
      node = path;
    }
    if (!node.node_ops.setattr) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    node.node_ops.setattr(node, { timestamp: Date.now() });
  },
  lchown: function (path, uid, gid) {
    FS.chown(path, uid, gid, true);
  },
  fchown: function (fd, uid, gid) {
    var stream = FS.getStream(fd);
    if (!stream) {
      throw new FS.ErrnoError(ERRNO_CODES.EBADF);
    }
    FS.chown(stream.node, uid, gid);
  },
  truncate: function (path, len) {
    if (len < 0) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    var node;
    if (typeof path === "string") {
      var lookup = FS.lookupPath(path, { follow: true });
      node = lookup.node;
    } else {
      node = path;
    }
    if (!node.node_ops.setattr) {
      throw new FS.ErrnoError(ERRNO_CODES.EPERM);
    }
    if (FS.isDir(node.mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.EISDIR);
    }
    if (!FS.isFile(node.mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    var err = FS.nodePermissions(node, "w");
    if (err) {
      throw new FS.ErrnoError(err);
    }
    node.node_ops.setattr(node, { size: len, timestamp: Date.now() });
  },
  ftruncate: function (fd, len) {
    var stream = FS.getStream(fd);
    if (!stream) {
      throw new FS.ErrnoError(ERRNO_CODES.EBADF);
    }
    if ((stream.flags & 2097155) === 0) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    FS.truncate(stream.node, len);
  },
  utime: function (path, atime, mtime) {
    var lookup = FS.lookupPath(path, { follow: true });
    var node = lookup.node;
    node.node_ops.setattr(node, { timestamp: Math.max(atime, mtime) });
  },
  open: function (path, flags, mode, fd_start, fd_end) {
    if (path === "") {
      throw new FS.ErrnoError(ERRNO_CODES.ENOENT);
    }
    flags = typeof flags === "string" ? FS.modeStringToFlags(flags) : flags;
    mode = typeof mode === "undefined" ? 438 : mode;
    if (flags & 64) {
      mode = (mode & 4095) | 32768;
    } else {
      mode = 0;
    }
    var node;
    if (typeof path === "object") {
      node = path;
    } else {
      path = PATH.normalize(path);
      try {
        var lookup = FS.lookupPath(path, { follow: !(flags & 131072) });
        node = lookup.node;
      } catch (e) {}
    }
    var created = false;
    if (flags & 64) {
      if (node) {
        if (flags & 128) {
          throw new FS.ErrnoError(ERRNO_CODES.EEXIST);
        }
      } else {
        node = FS.mknod(path, mode, 0);
        created = true;
      }
    }
    if (!node) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOENT);
    }
    if (FS.isChrdev(node.mode)) {
      flags &= ~512;
    }
    if (!created) {
      var err = FS.mayOpen(node, flags);
      if (err) {
        throw new FS.ErrnoError(err);
      }
    }
    if (flags & 512) {
      FS.truncate(node, 0);
    }
    flags &= ~(128 | 512);
    var stream = FS.createStream(
      {
        node: node,
        path: FS.getPath(node),
        flags: flags,
        seekable: true,
        position: 0,
        stream_ops: node.stream_ops,
        ungotten: [],
        error: false,
      },
      fd_start,
      fd_end
    );
    if (stream.stream_ops.open) {
      stream.stream_ops.open(stream);
    }
    if (Module["logReadFiles"] && !(flags & 1)) {
      if (!FS.readFiles) FS.readFiles = {};
      if (!(path in FS.readFiles)) {
        FS.readFiles[path] = 1;
        Module["printErr"]("read file: " + path);
      }
    }
    try {
      if (FS.trackingDelegate["onOpenFile"]) {
        var trackingFlags = 0;
        if ((flags & 2097155) !== 1) {
          trackingFlags |= FS.tracking.openFlags.READ;
        }
        if ((flags & 2097155) !== 0) {
          trackingFlags |= FS.tracking.openFlags.WRITE;
        }
        FS.trackingDelegate["onOpenFile"](path, trackingFlags);
      }
    } catch (e) {
      console.log(
        "FS.trackingDelegate['onOpenFile']('" +
          path +
          "', flags) threw an exception: " +
          e.message
      );
    }
    return stream;
  },
  close: function (stream) {
    try {
      if (stream.stream_ops.close) {
        stream.stream_ops.close(stream);
      }
    } catch (e) {
      throw e;
    } finally {
      FS.closeStream(stream.fd);
    }
  },
  llseek: function (stream, offset, whence) {
    if (!stream.seekable || !stream.stream_ops.llseek) {
      throw new FS.ErrnoError(ERRNO_CODES.ESPIPE);
    }
    stream.position = stream.stream_ops.llseek(stream, offset, whence);
    stream.ungotten = [];
    return stream.position;
  },
  read: function (stream, buffer, offset, length, position) {
    if (length < 0 || position < 0) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    if ((stream.flags & 2097155) === 1) {
      throw new FS.ErrnoError(ERRNO_CODES.EBADF);
    }
    if (FS.isDir(stream.node.mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.EISDIR);
    }
    if (!stream.stream_ops.read) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    var seeking = true;
    if (typeof position === "undefined") {
      position = stream.position;
      seeking = false;
    } else if (!stream.seekable) {
      throw new FS.ErrnoError(ERRNO_CODES.ESPIPE);
    }
    var bytesRead = stream.stream_ops.read(
      stream,
      buffer,
      offset,
      length,
      position
    );
    if (!seeking) stream.position += bytesRead;
    return bytesRead;
  },
  write: function (stream, buffer, offset, length, position, canOwn) {
    if (length < 0 || position < 0) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    if ((stream.flags & 2097155) === 0) {
      throw new FS.ErrnoError(ERRNO_CODES.EBADF);
    }
    if (FS.isDir(stream.node.mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.EISDIR);
    }
    if (!stream.stream_ops.write) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    if (stream.flags & 1024) {
      FS.llseek(stream, 0, 2);
    }
    var seeking = true;
    if (typeof position === "undefined") {
      position = stream.position;
      seeking = false;
    } else if (!stream.seekable) {
      throw new FS.ErrnoError(ERRNO_CODES.ESPIPE);
    }
    var bytesWritten = stream.stream_ops.write(
      stream,
      buffer,
      offset,
      length,
      position,
      canOwn
    );
    if (!seeking) stream.position += bytesWritten;
    try {
      if (stream.path && FS.trackingDelegate["onWriteToFile"])
        FS.trackingDelegate["onWriteToFile"](stream.path);
    } catch (e) {
      console.log(
        "FS.trackingDelegate['onWriteToFile']('" +
          path +
          "') threw an exception: " +
          e.message
      );
    }
    return bytesWritten;
  },
  allocate: function (stream, offset, length) {
    if (offset < 0 || length <= 0) {
      throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
    }
    if ((stream.flags & 2097155) === 0) {
      throw new FS.ErrnoError(ERRNO_CODES.EBADF);
    }
    if (!FS.isFile(stream.node.mode) && !FS.isDir(node.mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.ENODEV);
    }
    if (!stream.stream_ops.allocate) {
      throw new FS.ErrnoError(ERRNO_CODES.EOPNOTSUPP);
    }
    stream.stream_ops.allocate(stream, offset, length);
  },
  mmap: function (stream, buffer, offset, length, position, prot, flags) {
    if ((stream.flags & 2097155) === 1) {
      throw new FS.ErrnoError(ERRNO_CODES.EACCES);
    }
    if (!stream.stream_ops.mmap) {
      throw new FS.ErrnoError(ERRNO_CODES.ENODEV);
    }
    return stream.stream_ops.mmap(
      stream,
      buffer,
      offset,
      length,
      position,
      prot,
      flags
    );
  },
  ioctl: function (stream, cmd, arg) {
    if (!stream.stream_ops.ioctl) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOTTY);
    }
    return stream.stream_ops.ioctl(stream, cmd, arg);
  },
  readFile: function (path, opts) {
    opts = opts || {};
    opts.flags = opts.flags || "r";
    opts.encoding = opts.encoding || "binary";
    if (opts.encoding !== "utf8" && opts.encoding !== "binary") {
      throw new Error('Invalid encoding type "' + opts.encoding + '"');
    }
    var ret;
    var stream = FS.open(path, opts.flags);
    var stat = FS.stat(path);
    var length = stat.size;
    var buf = new Uint8Array(length);
    FS.read(stream, buf, 0, length, 0);
    if (opts.encoding === "utf8") {
      ret = "";
      var utf8 = new Runtime.UTF8Processor();
      for (var i = 0; i < length; i++) {
        ret += utf8.processCChar(buf[i]);
      }
    } else if (opts.encoding === "binary") {
      ret = buf;
    }
    FS.close(stream);
    return ret;
  },
  writeFile: function (path, data, opts) {
    opts = opts || {};
    opts.flags = opts.flags || "w";
    opts.encoding = opts.encoding || "utf8";
    if (opts.encoding !== "utf8" && opts.encoding !== "binary") {
      throw new Error('Invalid encoding type "' + opts.encoding + '"');
    }
    var stream = FS.open(path, opts.flags, opts.mode);
    if (opts.encoding === "utf8") {
      var utf8 = new Runtime.UTF8Processor();
      var buf = new Uint8Array(utf8.processJSString(data));
      FS.write(stream, buf, 0, buf.length, 0, opts.canOwn);
    } else if (opts.encoding === "binary") {
      FS.write(stream, data, 0, data.length, 0, opts.canOwn);
    }
    FS.close(stream);
  },
  cwd: function () {
    return FS.currentPath;
  },
  chdir: function (path) {
    var lookup = FS.lookupPath(path, { follow: true });
    if (!FS.isDir(lookup.node.mode)) {
      throw new FS.ErrnoError(ERRNO_CODES.ENOTDIR);
    }
    var err = FS.nodePermissions(lookup.node, "x");
    if (err) {
      throw new FS.ErrnoError(err);
    }
    FS.currentPath = lookup.path;
  },
  createDefaultDirectories: function () {
    FS.mkdir("/tmp");
    FS.mkdir("/home");
    FS.mkdir("/home/web_user");
  },
  createDefaultDevices: function () {
    FS.mkdir("/dev");
    FS.registerDevice(FS.makedev(1, 3), {
      read: function () {
        return 0;
      },
      write: function () {
        return 0;
      },
    });
    FS.mkdev("/dev/null", FS.makedev(1, 3));
    TTY.register(FS.makedev(5, 0), TTY.default_tty_ops);
    TTY.register(FS.makedev(6, 0), TTY.default_tty1_ops);
    FS.mkdev("/dev/tty", FS.makedev(5, 0));
    FS.mkdev("/dev/tty1", FS.makedev(6, 0));
    var random_device;
    if (typeof crypto !== "undefined") {
      var randomBuffer = new Uint8Array(1);
      random_device = function () {
        crypto.getRandomValues(randomBuffer);
        return randomBuffer[0];
      };
    } else if (ENVIRONMENT_IS_NODE) {
      random_device = function () {
        return require("crypto").randomBytes(1)[0];
      };
    } else {
      random_device = function () {
        return (Math.random() * 256) | 0;
      };
    }
    FS.createDevice("/dev", "random", random_device);
    FS.createDevice("/dev", "urandom", random_device);
    FS.mkdir("/dev/shm");
    FS.mkdir("/dev/shm/tmp");
  },
  createStandardStreams: function () {
    if (Module["stdin"]) {
      FS.createDevice("/dev", "stdin", Module["stdin"]);
    } else {
      FS.symlink("/dev/tty", "/dev/stdin");
    }
    if (Module["stdout"]) {
      FS.createDevice("/dev", "stdout", null, Module["stdout"]);
    } else {
      FS.symlink("/dev/tty", "/dev/stdout");
    }
    if (Module["stderr"]) {
      FS.createDevice("/dev", "stderr", null, Module["stderr"]);
    } else {
      FS.symlink("/dev/tty1", "/dev/stderr");
    }
    var stdin = FS.open("/dev/stdin", "r");
    HEAP32[_stdin >> 2] = FS.getPtrForStream(stdin);
    assert(stdin.fd === 0, "invalid handle for stdin (" + stdin.fd + ")");
    var stdout = FS.open("/dev/stdout", "w");
    HEAP32[_stdout >> 2] = FS.getPtrForStream(stdout);
    assert(stdout.fd === 1, "invalid handle for stdout (" + stdout.fd + ")");
    var stderr = FS.open("/dev/stderr", "w");
    HEAP32[_stderr >> 2] = FS.getPtrForStream(stderr);
    assert(stderr.fd === 2, "invalid handle for stderr (" + stderr.fd + ")");
  },
  ensureErrnoError: function () {
    if (FS.ErrnoError) return;
    FS.ErrnoError = function ErrnoError(errno, node) {
      this.node = node;
      this.setErrno = function (errno) {
        this.errno = errno;
        for (var key in ERRNO_CODES) {
          if (ERRNO_CODES[key] === errno) {
            this.code = key;
            break;
          }
        }
      };
      this.setErrno(errno);
      this.message = ERRNO_MESSAGES[errno];
    };
    FS.ErrnoError.prototype = new Error();
    FS.ErrnoError.prototype.constructor = FS.ErrnoError;
    [ERRNO_CODES.ENOENT].forEach(function (code) {
      FS.genericErrors[code] = new FS.ErrnoError(code);
      FS.genericErrors[code].stack = "<generic error, no stack>";
    });
  },
  staticInit: function () {
    FS.ensureErrnoError();
    FS.nameTable = new Array(4096);
    FS.mount(MEMFS, {}, "/");
    FS.createDefaultDirectories();
    FS.createDefaultDevices();
  },
  init: function (input, output, error) {
    assert(
      !FS.init.initialized,
      "FS.init was previously called. If you want to initialize later with custom parameters, remove any earlier calls (note that one is automatically added to the generated code)"
    );
    FS.init.initialized = true;
    FS.ensureErrnoError();
    Module["stdin"] = input || Module["stdin"];
    Module["stdout"] = output || Module["stdout"];
    Module["stderr"] = error || Module["stderr"];
    FS.createStandardStreams();
  },
  quit: function () {
    FS.init.initialized = false;
    for (var i = 0; i < FS.streams.length; i++) {
      var stream = FS.streams[i];
      if (!stream) {
        continue;
      }
      FS.close(stream);
    }
  },
  getMode: function (canRead, canWrite) {
    var mode = 0;
    if (canRead) mode |= 292 | 73;
    if (canWrite) mode |= 146;
    return mode;
  },
  joinPath: function (parts, forceRelative) {
    var path = PATH.join.apply(null, parts);
    if (forceRelative && path[0] == "/") path = path.substr(1);
    return path;
  },
  absolutePath: function (relative, base) {
    return PATH.resolve(base, relative);
  },
  standardizePath: function (path) {
    return PATH.normalize(path);
  },
  findObject: function (path, dontResolveLastLink) {
    var ret = FS.analyzePath(path, dontResolveLastLink);
    if (ret.exists) {
      return ret.object;
    } else {
      ___setErrNo(ret.error);
      return null;
    }
  },
  analyzePath: function (path, dontResolveLastLink) {
    try {
      var lookup = FS.lookupPath(path, { follow: !dontResolveLastLink });
      path = lookup.path;
    } catch (e) {}
    var ret = {
      isRoot: false,
      exists: false,
      error: 0,
      name: null,
      path: null,
      object: null,
      parentExists: false,
      parentPath: null,
      parentObject: null,
    };
    try {
      var lookup = FS.lookupPath(path, { parent: true });
      ret.parentExists = true;
      ret.parentPath = lookup.path;
      ret.parentObject = lookup.node;
      ret.name = PATH.basename(path);
      lookup = FS.lookupPath(path, { follow: !dontResolveLastLink });
      ret.exists = true;
      ret.path = lookup.path;
      ret.object = lookup.node;
      ret.name = lookup.node.name;
      ret.isRoot = lookup.path === "/";
    } catch (e) {
      ret.error = e.errno;
    }
    return ret;
  },
  createFolder: function (parent, name, canRead, canWrite) {
    var path = PATH.join2(
      typeof parent === "string" ? parent : FS.getPath(parent),
      name
    );
    var mode = FS.getMode(canRead, canWrite);
    return FS.mkdir(path, mode);
  },
  createPath: function (parent, path, canRead, canWrite) {
    parent = typeof parent === "string" ? parent : FS.getPath(parent);
    var parts = path.split("/").reverse();
    while (parts.length) {
      var part = parts.pop();
      if (!part) continue;
      var current = PATH.join2(parent, part);
      try {
        FS.mkdir(current);
      } catch (e) {}
      parent = current;
    }
    return current;
  },
  createFile: function (parent, name, properties, canRead, canWrite) {
    var path = PATH.join2(
      typeof parent === "string" ? parent : FS.getPath(parent),
      name
    );
    var mode = FS.getMode(canRead, canWrite);
    return FS.create(path, mode);
  },
  createDataFile: function (parent, name, data, canRead, canWrite, canOwn) {
    var path = name
      ? PATH.join2(
          typeof parent === "string" ? parent : FS.getPath(parent),
          name
        )
      : parent;
    var mode = FS.getMode(canRead, canWrite);
    var node = FS.create(path, mode);
    if (data) {
      if (typeof data === "string") {
        var arr = new Array(data.length);
        for (var i = 0, len = data.length; i < len; ++i)
          arr[i] = data.charCodeAt(i);
        data = arr;
      }
      FS.chmod(node, mode | 146);
      var stream = FS.open(node, "w");
      FS.write(stream, data, 0, data.length, 0, canOwn);
      FS.close(stream);
      FS.chmod(node, mode);
    }
    return node;
  },
  createDevice: function (parent, name, input, output) {
    var path = PATH.join2(
      typeof parent === "string" ? parent : FS.getPath(parent),
      name
    );
    var mode = FS.getMode(!!input, !!output);
    if (!FS.createDevice.major) FS.createDevice.major = 64;
    var dev = FS.makedev(FS.createDevice.major++, 0);
    FS.registerDevice(dev, {
      open: function (stream) {
        stream.seekable = false;
      },
      close: function (stream) {
        if (output && output.buffer && output.buffer.length) {
          output(10);
        }
      },
      read: function (stream, buffer, offset, length, pos) {
        var bytesRead = 0;
        for (var i = 0; i < length; i++) {
          var result;
          try {
            result = input();
          } catch (e) {
            throw new FS.ErrnoError(ERRNO_CODES.EIO);
          }
          if (result === undefined && bytesRead === 0) {
            throw new FS.ErrnoError(ERRNO_CODES.EAGAIN);
          }
          if (result === null || result === undefined) break;
          bytesRead++;
          buffer[offset + i] = result;
        }
        if (bytesRead) {
          stream.node.timestamp = Date.now();
        }
        return bytesRead;
      },
      write: function (stream, buffer, offset, length, pos) {
        for (var i = 0; i < length; i++) {
          try {
            output(buffer[offset + i]);
          } catch (e) {
            throw new FS.ErrnoError(ERRNO_CODES.EIO);
          }
        }
        if (length) {
          stream.node.timestamp = Date.now();
        }
        return i;
      },
    });
    return FS.mkdev(path, mode, dev);
  },
  createLink: function (parent, name, target, canRead, canWrite) {
    var path = PATH.join2(
      typeof parent === "string" ? parent : FS.getPath(parent),
      name
    );
    return FS.symlink(target, path);
  },
  forceLoadFile: function (obj) {
    if (obj.isDevice || obj.isFolder || obj.link || obj.contents) return true;
    var success = true;
    if (typeof XMLHttpRequest !== "undefined") {
      throw new Error(
        "Lazy loading should have been performed (contents set) in createLazyFile, but it was not. Lazy loading only works in web workers. Use --embed-file or --preload-file in emcc on the main thread."
      );
    } else if (Module["read"]) {
      try {
        obj.contents = intArrayFromString(Module["read"](obj.url), true);
        obj.usedBytes = obj.contents.length;
      } catch (e) {
        success = false;
      }
    } else {
      throw new Error("Cannot load without read() or XMLHttpRequest.");
    }
    if (!success) ___setErrNo(ERRNO_CODES.EIO);
    return success;
  },
  createLazyFile: function (parent, name, url, canRead, canWrite) {
    function LazyUint8Array() {
      this.lengthKnown = false;
      this.chunks = [];
    }
    LazyUint8Array.prototype.get = function LazyUint8Array_get(idx) {
      if (idx > this.length - 1 || idx < 0) {
        return undefined;
      }
      var chunkOffset = idx % this.chunkSize;
      var chunkNum = (idx / this.chunkSize) | 0;
      return this.getter(chunkNum)[chunkOffset];
    };
    LazyUint8Array.prototype.setDataGetter = function LazyUint8Array_setDataGetter(
      getter
    ) {
      this.getter = getter;
    };
    LazyUint8Array.prototype.cacheLength = function LazyUint8Array_cacheLength() {
      var xhr = new XMLHttpRequest();
      xhr.open("HEAD", url, false);
      xhr.send(null);
      if (!((xhr.status >= 200 && xhr.status < 300) || xhr.status === 304))
        throw new Error("Couldn't load " + url + ". Status: " + xhr.status);
      var datalength = Number(xhr.getResponseHeader("Content-length"));
      var header;
      var hasByteServing =
        (header = xhr.getResponseHeader("Accept-Ranges")) && header === "bytes";
      var chunkSize = 1024 * 1024;
      if (!hasByteServing) chunkSize = datalength;
      var doXHR = function (from, to) {
        if (from > to)
          throw new Error(
            "invalid range (" + from + ", " + to + ") or no bytes requested!"
          );
        if (to > datalength - 1)
          throw new Error(
            "only " + datalength + " bytes available! programmer error!"
          );
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url, false);
        if (datalength !== chunkSize)
          xhr.setRequestHeader("Range", "bytes=" + from + "-" + to);
        if (typeof Uint8Array != "undefined") xhr.responseType = "arraybuffer";
        if (xhr.overrideMimeType) {
          xhr.overrideMimeType("text/plain; charset=x-user-defined");
        }
        xhr.send(null);
        if (!((xhr.status >= 200 && xhr.status < 300) || xhr.status === 304))
          throw new Error("Couldn't load " + url + ". Status: " + xhr.status);
        if (xhr.response !== undefined) {
          return new Uint8Array(xhr.response || []);
        } else {
          return intArrayFromString(xhr.responseText || "", true);
        }
      };
      var lazyArray = this;
      lazyArray.setDataGetter(function (chunkNum) {
        var start = chunkNum * chunkSize;
        var end = (chunkNum + 1) * chunkSize - 1;
        end = Math.min(end, datalength - 1);
        if (typeof lazyArray.chunks[chunkNum] === "undefined") {
          lazyArray.chunks[chunkNum] = doXHR(start, end);
        }
        if (typeof lazyArray.chunks[chunkNum] === "undefined")
          throw new Error("doXHR failed!");
        return lazyArray.chunks[chunkNum];
      });
      this._length = datalength;
      this._chunkSize = chunkSize;
      this.lengthKnown = true;
    };
    if (typeof XMLHttpRequest !== "undefined") {
      if (!ENVIRONMENT_IS_WORKER)
        throw "Cannot do synchronous binary XHRs outside webworkers in modern browsers. Use --embed-file or --preload-file in emcc";
      var lazyArray = new LazyUint8Array();
      Object.defineProperty(lazyArray, "length", {
        get: function () {
          if (!this.lengthKnown) {
            this.cacheLength();
          }
          return this._length;
        },
      });
      Object.defineProperty(lazyArray, "chunkSize", {
        get: function () {
          if (!this.lengthKnown) {
            this.cacheLength();
          }
          return this._chunkSize;
        },
      });
      var properties = { isDevice: false, contents: lazyArray };
    } else {
      var properties = { isDevice: false, url: url };
    }
    var node = FS.createFile(parent, name, properties, canRead, canWrite);
    if (properties.contents) {
      node.contents = properties.contents;
    } else if (properties.url) {
      node.contents = null;
      node.url = properties.url;
    }
    Object.defineProperty(node, "usedBytes", {
      get: function () {
        return this.contents.length;
      },
    });
    var stream_ops = {};
    var keys = Object.keys(node.stream_ops);
    keys.forEach(function (key) {
      var fn = node.stream_ops[key];
      stream_ops[key] = function forceLoadLazyFile() {
        if (!FS.forceLoadFile(node)) {
          throw new FS.ErrnoError(ERRNO_CODES.EIO);
        }
        return fn.apply(null, arguments);
      };
    });
    stream_ops.read = function stream_ops_read(
      stream,
      buffer,
      offset,
      length,
      position
    ) {
      if (!FS.forceLoadFile(node)) {
        throw new FS.ErrnoError(ERRNO_CODES.EIO);
      }
      var contents = stream.node.contents;
      if (position >= contents.length) return 0;
      var size = Math.min(contents.length - position, length);
      assert(size >= 0);
      if (contents.slice) {
        for (var i = 0; i < size; i++) {
          buffer[offset + i] = contents[position + i];
        }
      } else {
        for (var i = 0; i < size; i++) {
          buffer[offset + i] = contents.get(position + i);
        }
      }
      return size;
    };
    node.stream_ops = stream_ops;
    return node;
  },
  createPreloadedFile: function (
    parent,
    name,
    url,
    canRead,
    canWrite,
    onload,
    onerror,
    dontCreateFile,
    canOwn
  ) {
    Browser.init();
    var fullname = name ? PATH.resolve(PATH.join2(parent, name)) : parent;
    function processData(byteArray) {
      function finish(byteArray) {
        if (!dontCreateFile) {
          FS.createDataFile(parent, name, byteArray, canRead, canWrite, canOwn);
        }
        if (onload) onload();
        removeRunDependency("cp " + fullname);
      }
      var handled = false;
      Module["preloadPlugins"].forEach(function (plugin) {
        if (handled) return;
        if (plugin["canHandle"](fullname)) {
          plugin["handle"](byteArray, fullname, finish, function () {
            if (onerror) onerror();
            removeRunDependency("cp " + fullname);
          });
          handled = true;
        }
      });
      if (!handled) finish(byteArray);
    }
    addRunDependency("cp " + fullname);
    if (typeof url == "string") {
      Browser.asyncLoad(
        url,
        function (byteArray) {
          processData(byteArray);
        },
        onerror
      );
    } else {
      processData(url);
    }
  },
  indexedDB: function () {
    return (
      window.indexedDB ||
      window.mozIndexedDB ||
      window.webkitIndexedDB ||
      window.msIndexedDB
    );
  },
  DB_NAME: function () {
    return "EM_FS_" + window.location.pathname;
  },
  DB_VERSION: 20,
  DB_STORE_NAME: "FILE_DATA",
  saveFilesToDB: function (paths, onload, onerror) {
    onload = onload || function () {};
    onerror = onerror || function () {};
    var indexedDB = FS.indexedDB();
    try {
      var openRequest = indexedDB.open(FS.DB_NAME(), FS.DB_VERSION);
    } catch (e) {
      return onerror(e);
    }
    openRequest.onupgradeneeded = function openRequest_onupgradeneeded() {
      console.log("creating db");
      var db = openRequest.result;
      db.createObjectStore(FS.DB_STORE_NAME);
    };
    openRequest.onsuccess = function openRequest_onsuccess() {
      var db = openRequest.result;
      var transaction = db.transaction([FS.DB_STORE_NAME], "readwrite");
      var files = transaction.objectStore(FS.DB_STORE_NAME);
      var ok = 0,
        fail = 0,
        total = paths.length;
      function finish() {
        if (fail == 0) onload();
        else onerror();
      }
      paths.forEach(function (path) {
        var putRequest = files.put(FS.analyzePath(path).object.contents, path);
        putRequest.onsuccess = function putRequest_onsuccess() {
          ok++;
          if (ok + fail == total) finish();
        };
        putRequest.onerror = function putRequest_onerror() {
          fail++;
          if (ok + fail == total) finish();
        };
      });
      transaction.onerror = onerror;
    };
    openRequest.onerror = onerror;
  },
  loadFilesFromDB: function (paths, onload, onerror) {
    onload = onload || function () {};
    onerror = onerror || function () {};
    var indexedDB = FS.indexedDB();
    try {
      var openRequest = indexedDB.open(FS.DB_NAME(), FS.DB_VERSION);
    } catch (e) {
      return onerror(e);
    }
    openRequest.onupgradeneeded = onerror;
    openRequest.onsuccess = function openRequest_onsuccess() {
      var db = openRequest.result;
      try {
        var transaction = db.transaction([FS.DB_STORE_NAME], "readonly");
      } catch (e) {
        onerror(e);
        return;
      }
      var files = transaction.objectStore(FS.DB_STORE_NAME);
      var ok = 0,
        fail = 0,
        total = paths.length;
      function finish() {
        if (fail == 0) onload();
        else onerror();
      }
      paths.forEach(function (path) {
        var getRequest = files.get(path);
        getRequest.onsuccess = function getRequest_onsuccess() {
          if (FS.analyzePath(path).exists) {
            FS.unlink(path);
          }
          FS.createDataFile(
            PATH.dirname(path),
            PATH.basename(path),
            getRequest.result,
            true,
            true,
            true
          );
          ok++;
          if (ok + fail == total) finish();
        };
        getRequest.onerror = function getRequest_onerror() {
          fail++;
          if (ok + fail == total) finish();
        };
      });
      transaction.onerror = onerror;
    };
    openRequest.onerror = onerror;
  },
};
var PATH = {
  splitPath: function (filename) {
    var splitPathRe = /^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/;
    return splitPathRe.exec(filename).slice(1);
  },
  normalizeArray: function (parts, allowAboveRoot) {
    var up = 0;
    for (var i = parts.length - 1; i >= 0; i--) {
      var last = parts[i];
      if (last === ".") {
        parts.splice(i, 1);
      } else if (last === "..") {
        parts.splice(i, 1);
        up++;
      } else if (up) {
        parts.splice(i, 1);
        up--;
      }
    }
    if (allowAboveRoot) {
      for (; up--; up) {
        parts.unshift("..");
      }
    }
    return parts;
  },
  normalize: function (path) {
    var isAbsolute = path.charAt(0) === "/",
      trailingSlash = path.substr(-1) === "/";
    path = PATH.normalizeArray(
      path.split("/").filter(function (p) {
        return !!p;
      }),
      !isAbsolute
    ).join("/");
    if (!path && !isAbsolute) {
      path = ".";
    }
    if (path && trailingSlash) {
      path += "/";
    }
    return (isAbsolute ? "/" : "") + path;
  },
  dirname: function (path) {
    var result = PATH.splitPath(path),
      root = result[0],
      dir = result[1];
    if (!root && !dir) {
      return ".";
    }
    if (dir) {
      dir = dir.substr(0, dir.length - 1);
    }
    return root + dir;
  },
  basename: function (path) {
    if (path === "/") return "/";
    var lastSlash = path.lastIndexOf("/");
    if (lastSlash === -1) return path;
    return path.substr(lastSlash + 1);
  },
  extname: function (path) {
    return PATH.splitPath(path)[3];
  },
  join: function () {
    var paths = Array.prototype.slice.call(arguments, 0);
    return PATH.normalize(paths.join("/"));
  },
  join2: function (l, r) {
    return PATH.normalize(l + "/" + r);
  },
  resolve: function () {
    var resolvedPath = "",
      resolvedAbsolute = false;
    for (var i = arguments.length - 1; i >= -1 && !resolvedAbsolute; i--) {
      var path = i >= 0 ? arguments[i] : FS.cwd();
      if (typeof path !== "string") {
        throw new TypeError("Arguments to path.resolve must be strings");
      } else if (!path) {
        return "";
      }
      resolvedPath = path + "/" + resolvedPath;
      resolvedAbsolute = path.charAt(0) === "/";
    }
    resolvedPath = PATH.normalizeArray(
      resolvedPath.split("/").filter(function (p) {
        return !!p;
      }),
      !resolvedAbsolute
    ).join("/");
    return (resolvedAbsolute ? "/" : "") + resolvedPath || ".";
  },
  relative: function (from, to) {
    from = PATH.resolve(from).substr(1);
    to = PATH.resolve(to).substr(1);
    function trim(arr) {
      var start = 0;
      for (; start < arr.length; start++) {
        if (arr[start] !== "") break;
      }
      var end = arr.length - 1;
      for (; end >= 0; end--) {
        if (arr[end] !== "") break;
      }
      if (start > end) return [];
      return arr.slice(start, end - start + 1);
    }
    var fromParts = trim(from.split("/"));
    var toParts = trim(to.split("/"));
    var length = Math.min(fromParts.length, toParts.length);
    var samePartsLength = length;
    for (var i = 0; i < length; i++) {
      if (fromParts[i] !== toParts[i]) {
        samePartsLength = i;
        break;
      }
    }
    var outputParts = [];
    for (var i = samePartsLength; i < fromParts.length; i++) {
      outputParts.push("..");
    }
    outputParts = outputParts.concat(toParts.slice(samePartsLength));
    return outputParts.join("/");
  },
};
function _emscripten_set_main_loop_timing(mode, value) {
  Browser.mainLoop.timingMode = mode;
  Browser.mainLoop.timingValue = value;
  if (!Browser.mainLoop.func) {
    return 1;
  }
  if (mode == 0) {
    Browser.mainLoop.scheduler = function Browser_mainLoop_scheduler() {
      setTimeout(Browser.mainLoop.runner, value);
    };
    Browser.mainLoop.method = "timeout";
  } else if (mode == 1) {
    Browser.mainLoop.scheduler = function Browser_mainLoop_scheduler() {
      Browser.requestAnimationFrame(Browser.mainLoop.runner);
    };
    Browser.mainLoop.method = "rAF";
  }
  return 0;
}
function _emscripten_set_main_loop(func, fps, simulateInfiniteLoop, arg) {
  Module["noExitRuntime"] = true;
  assert(
    !Browser.mainLoop.func,
    "emscripten_set_main_loop: there can only be one main loop function at once: call emscripten_cancel_main_loop to cancel the previous one before setting a new one with different parameters."
  );
  Browser.mainLoop.func = func;
  Browser.mainLoop.arg = arg;
  var thisMainLoopId = Browser.mainLoop.currentlyRunningMainloop;
  Browser.mainLoop.runner = function Browser_mainLoop_runner() {
    if (ABORT) return;
    if (Browser.mainLoop.queue.length > 0) {
      var start = Date.now();
      var blocker = Browser.mainLoop.queue.shift();
      blocker.func(blocker.arg);
      if (Browser.mainLoop.remainingBlockers) {
        var remaining = Browser.mainLoop.remainingBlockers;
        var next = remaining % 1 == 0 ? remaining - 1 : Math.floor(remaining);
        if (blocker.counted) {
          Browser.mainLoop.remainingBlockers = next;
        } else {
          next = next + 0.5;
          Browser.mainLoop.remainingBlockers = (8 * remaining + next) / 9;
        }
      }
      console.log(
        'main loop blocker "' +
          blocker.name +
          '" took ' +
          (Date.now() - start) +
          " ms"
      );
      Browser.mainLoop.updateStatus();
      setTimeout(Browser.mainLoop.runner, 0);
      return;
    }
    if (thisMainLoopId < Browser.mainLoop.currentlyRunningMainloop) return;
    Browser.mainLoop.currentFrameNumber =
      (Browser.mainLoop.currentFrameNumber + 1) | 0;
    if (
      Browser.mainLoop.timingMode == 1 &&
      Browser.mainLoop.timingValue > 1 &&
      Browser.mainLoop.currentFrameNumber % Browser.mainLoop.timingValue != 0
    ) {
      Browser.mainLoop.scheduler();
      return;
    }
    if (Browser.mainLoop.method === "timeout" && Module.ctx) {
      Module.printErr(
        "Looks like you are rendering without using requestAnimationFrame for the main loop. You should use 0 for the frame rate in emscripten_set_main_loop in order to use requestAnimationFrame, as that can greatly improve your frame rates!"
      );
      Browser.mainLoop.method = "";
    }
    Browser.mainLoop.runIter(function () {
      if (typeof arg !== "undefined") {
        Runtime.dynCall("vi", func, [arg]);
      } else {
        Runtime.dynCall("v", func);
      }
    });
    if (thisMainLoopId < Browser.mainLoop.currentlyRunningMainloop) return;
    if (typeof SDL === "object" && SDL.audio && SDL.audio.queueNewAudioData)
      SDL.audio.queueNewAudioData();
    Browser.mainLoop.scheduler();
  };
  if (fps && fps > 0) _emscripten_set_main_loop_timing(0, 1e3 / fps);
  else _emscripten_set_main_loop_timing(1, 1);
  Browser.mainLoop.scheduler();
  if (simulateInfiniteLoop) {
    throw "SimulateInfiniteLoop";
  }
}
var Browser = {
  mainLoop: {
    scheduler: null,
    method: "",
    currentlyRunningMainloop: 0,
    func: null,
    arg: 0,
    timingMode: 0,
    timingValue: 0,
    currentFrameNumber: 0,
    queue: [],
    pause: function () {
      Browser.mainLoop.scheduler = null;
      Browser.mainLoop.currentlyRunningMainloop++;
    },
    resume: function () {
      Browser.mainLoop.currentlyRunningMainloop++;
      var timingMode = Browser.mainLoop.timingMode;
      var timingValue = Browser.mainLoop.timingValue;
      var func = Browser.mainLoop.func;
      Browser.mainLoop.func = null;
      _emscripten_set_main_loop(func, 0, false, Browser.mainLoop.arg);
      _emscripten_set_main_loop_timing(timingMode, timingValue);
    },
    updateStatus: function () {
      if (Module["setStatus"]) {
        var message = Module["statusMessage"] || "Please wait...";
        var remaining = Browser.mainLoop.remainingBlockers;
        var expected = Browser.mainLoop.expectedBlockers;
        if (remaining) {
          if (remaining < expected) {
            Module["setStatus"](
              message + " (" + (expected - remaining) + "/" + expected + ")"
            );
          } else {
            Module["setStatus"](message);
          }
        } else {
          Module["setStatus"]("");
        }
      }
    },
    runIter: function (func) {
      if (ABORT) return;
      if (Module["preMainLoop"]) {
        var preRet = Module["preMainLoop"]();
        if (preRet === false) {
          return;
        }
      }
      try {
        func();
      } catch (e) {
        if (e instanceof ExitStatus) {
          return;
        } else {
          if (e && typeof e === "object" && e.stack)
            Module.printErr("exception thrown: " + [e, e.stack]);
          throw e;
        }
      }
      if (Module["postMainLoop"]) Module["postMainLoop"]();
    },
  },
  isFullScreen: false,
  pointerLock: false,
  moduleContextCreatedCallbacks: [],
  workers: [],
  init: function () {
    if (!Module["preloadPlugins"]) Module["preloadPlugins"] = [];
    if (Browser.initted) return;
    Browser.initted = true;
    try {
      new Blob();
      Browser.hasBlobConstructor = true;
    } catch (e) {
      Browser.hasBlobConstructor = false;
      console.log(
        "warning: no blob constructor, cannot create blobs with mimetypes"
      );
    }
    Browser.BlobBuilder =
      typeof MozBlobBuilder != "undefined"
        ? MozBlobBuilder
        : typeof WebKitBlobBuilder != "undefined"
        ? WebKitBlobBuilder
        : !Browser.hasBlobConstructor
        ? console.log("warning: no BlobBuilder")
        : null;
    Browser.URLObject =
      typeof window != "undefined"
        ? window.URL
          ? window.URL
          : window.webkitURL
        : undefined;
    if (!Module.noImageDecoding && typeof Browser.URLObject === "undefined") {
      console.log(
        "warning: Browser does not support creating object URLs. Built-in browser image decoding will not be available."
      );
      Module.noImageDecoding = true;
    }
    var imagePlugin = {};
    imagePlugin["canHandle"] = function imagePlugin_canHandle(name) {
      return !Module.noImageDecoding && /\.(jpg|jpeg|png|bmp)$/i.test(name);
    };
    imagePlugin["handle"] = function imagePlugin_handle(
      byteArray,
      name,
      onload,
      onerror
    ) {
      var b = null;
      if (Browser.hasBlobConstructor) {
        try {
          b = new Blob([byteArray], { type: Browser.getMimetype(name) });
          if (b.size !== byteArray.length) {
            b = new Blob([new Uint8Array(byteArray).buffer], {
              type: Browser.getMimetype(name),
            });
          }
        } catch (e) {
          Runtime.warnOnce(
            "Blob constructor present but fails: " +
              e +
              "; falling back to blob builder"
          );
        }
      }
      if (!b) {
        var bb = new Browser.BlobBuilder();
        bb.append(new Uint8Array(byteArray).buffer);
        b = bb.getBlob();
      }
      var url = Browser.URLObject.createObjectURL(b);
      var img = new Image();
      img.onload = function img_onload() {
        assert(img.complete, "Image " + name + " could not be decoded");
        var canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        var ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        Module["preloadedImages"][name] = canvas;
        Browser.URLObject.revokeObjectURL(url);
        if (onload) onload(byteArray);
      };
      img.onerror = function img_onerror(event) {
        console.log("Image " + url + " could not be decoded");
        if (onerror) onerror();
      };
      img.src = url;
    };
    Module["preloadPlugins"].push(imagePlugin);
    var audioPlugin = {};
    audioPlugin["canHandle"] = function audioPlugin_canHandle(name) {
      return (
        !Module.noAudioDecoding &&
        name.substr(-4) in { ".ogg": 1, ".wav": 1, ".mp3": 1 }
      );
    };
    audioPlugin["handle"] = function audioPlugin_handle(
      byteArray,
      name,
      onload,
      onerror
    ) {
      var done = false;
      function finish(audio) {
        if (done) return;
        done = true;
        Module["preloadedAudios"][name] = audio;
        if (onload) onload(byteArray);
      }
      function fail() {
        if (done) return;
        done = true;
        Module["preloadedAudios"][name] = new Audio();
        if (onerror) onerror();
      }
      if (Browser.hasBlobConstructor) {
        try {
          var b = new Blob([byteArray], { type: Browser.getMimetype(name) });
        } catch (e) {
          return fail();
        }
        var url = Browser.URLObject.createObjectURL(b);
        var audio = new Audio();
        audio.addEventListener(
          "canplaythrough",
          function () {
            finish(audio);
          },
          false
        );
        audio.onerror = function audio_onerror(event) {
          if (done) return;
          console.log(
            "warning: browser could not fully decode audio " +
              name +
              ", trying slower base64 approach"
          );
          function encode64(data) {
            var BASE =
              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var PAD = "=";
            var ret = "";
            var leftchar = 0;
            var leftbits = 0;
            for (var i = 0; i < data.length; i++) {
              leftchar = (leftchar << 8) | data[i];
              leftbits += 8;
              while (leftbits >= 6) {
                var curr = (leftchar >> (leftbits - 6)) & 63;
                leftbits -= 6;
                ret += BASE[curr];
              }
            }
            if (leftbits == 2) {
              ret += BASE[(leftchar & 3) << 4];
              ret += PAD + PAD;
            } else if (leftbits == 4) {
              ret += BASE[(leftchar & 15) << 2];
              ret += PAD;
            }
            return ret;
          }
          audio.src =
            "data:audio/x-" +
            name.substr(-3) +
            ";base64," +
            encode64(byteArray);
          finish(audio);
        };
        audio.src = url;
        Browser.safeSetTimeout(function () {
          finish(audio);
        }, 1e4);
      } else {
        return fail();
      }
    };
    Module["preloadPlugins"].push(audioPlugin);
    var canvas = Module["canvas"];
    function pointerLockChange() {
      Browser.pointerLock =
        document["pointerLockElement"] === canvas ||
        document["mozPointerLockElement"] === canvas ||
        document["webkitPointerLockElement"] === canvas ||
        document["msPointerLockElement"] === canvas;
    }
    if (canvas) {
      canvas.requestPointerLock =
        canvas["requestPointerLock"] ||
        canvas["mozRequestPointerLock"] ||
        canvas["webkitRequestPointerLock"] ||
        canvas["msRequestPointerLock"] ||
        function () {};
      canvas.exitPointerLock =
        document["exitPointerLock"] ||
        document["mozExitPointerLock"] ||
        document["webkitExitPointerLock"] ||
        document["msExitPointerLock"] ||
        function () {};
      canvas.exitPointerLock = canvas.exitPointerLock.bind(document);
      document.addEventListener("pointerlockchange", pointerLockChange, false);
      document.addEventListener(
        "mozpointerlockchange",
        pointerLockChange,
        false
      );
      document.addEventListener(
        "webkitpointerlockchange",
        pointerLockChange,
        false
      );
      document.addEventListener(
        "mspointerlockchange",
        pointerLockChange,
        false
      );
      if (Module["elementPointerLock"]) {
        canvas.addEventListener(
          "click",
          function (ev) {
            if (!Browser.pointerLock && canvas.requestPointerLock) {
              canvas.requestPointerLock();
              ev.preventDefault();
            }
          },
          false
        );
      }
    }
  },
  createContext: function (
    canvas,
    useWebGL,
    setInModule,
    webGLContextAttributes
  ) {
    if (useWebGL && Module.ctx && canvas == Module.canvas) return Module.ctx;
    var ctx;
    var contextHandle;
    if (useWebGL) {
      var contextAttributes = { antialias: false, alpha: false };
      if (webGLContextAttributes) {
        for (var attribute in webGLContextAttributes) {
          contextAttributes[attribute] = webGLContextAttributes[attribute];
        }
      }
      contextHandle = GL.createContext(canvas, contextAttributes);
      if (contextHandle) {
        ctx = GL.getContext(contextHandle).GLctx;
      }
      canvas.style.backgroundColor = "black";
    } else {
      ctx = canvas.getContext("2d");
    }
    if (!ctx) return null;
    if (setInModule) {
      if (!useWebGL)
        assert(
          typeof GLctx === "undefined",
          "cannot set in module if GLctx is used, but we are a non-GL context that would replace it"
        );
      Module.ctx = ctx;
      if (useWebGL) GL.makeContextCurrent(contextHandle);
      Module.useWebGL = useWebGL;
      Browser.moduleContextCreatedCallbacks.forEach(function (callback) {
        callback();
      });
      Browser.init();
    }
    return ctx;
  },
  destroyContext: function (canvas, useWebGL, setInModule) {},
  fullScreenHandlersInstalled: false,
  lockPointer: undefined,
  resizeCanvas: undefined,
  requestFullScreen: function (lockPointer, resizeCanvas) {
    Browser.lockPointer = lockPointer;
    Browser.resizeCanvas = resizeCanvas;
    if (typeof Browser.lockPointer === "undefined") Browser.lockPointer = true;
    if (typeof Browser.resizeCanvas === "undefined")
      Browser.resizeCanvas = false;
    var canvas = Module["canvas"];
    function fullScreenChange() {
      Browser.isFullScreen = false;
      var canvasContainer = canvas.parentNode;
      if (
        (document["webkitFullScreenElement"] ||
          document["webkitFullscreenElement"] ||
          document["mozFullScreenElement"] ||
          document["mozFullscreenElement"] ||
          document["fullScreenElement"] ||
          document["fullscreenElement"] ||
          document["msFullScreenElement"] ||
          document["msFullscreenElement"] ||
          document["webkitCurrentFullScreenElement"]) === canvasContainer
      ) {
        canvas.cancelFullScreen =
          document["cancelFullScreen"] ||
          document["mozCancelFullScreen"] ||
          document["webkitCancelFullScreen"] ||
          document["msExitFullscreen"] ||
          document["exitFullscreen"] ||
          function () {};
        canvas.cancelFullScreen = canvas.cancelFullScreen.bind(document);
        if (Browser.lockPointer) canvas.requestPointerLock();
        Browser.isFullScreen = true;
        if (Browser.resizeCanvas) Browser.setFullScreenCanvasSize();
      } else {
        canvasContainer.parentNode.insertBefore(canvas, canvasContainer);
        canvasContainer.parentNode.removeChild(canvasContainer);
        if (Browser.resizeCanvas) Browser.setWindowedCanvasSize();
      }
      if (Module["onFullScreen"]) Module["onFullScreen"](Browser.isFullScreen);
      Browser.updateCanvasDimensions(canvas);
    }
    if (!Browser.fullScreenHandlersInstalled) {
      Browser.fullScreenHandlersInstalled = true;
      document.addEventListener("fullscreenchange", fullScreenChange, false);
      document.addEventListener("mozfullscreenchange", fullScreenChange, false);
      document.addEventListener(
        "webkitfullscreenchange",
        fullScreenChange,
        false
      );
      document.addEventListener("MSFullscreenChange", fullScreenChange, false);
    }
    var canvasContainer = document.createElement("div");
    canvas.parentNode.insertBefore(canvasContainer, canvas);
    canvasContainer.appendChild(canvas);
    canvasContainer.requestFullScreen =
      canvasContainer["requestFullScreen"] ||
      canvasContainer["mozRequestFullScreen"] ||
      canvasContainer["msRequestFullscreen"] ||
      (canvasContainer["webkitRequestFullScreen"]
        ? function () {
            canvasContainer["webkitRequestFullScreen"](
              Element["ALLOW_KEYBOARD_INPUT"]
            );
          }
        : null);
    canvasContainer.requestFullScreen();
  },
  nextRAF: 0,
  fakeRequestAnimationFrame: function (func) {
    var now = Date.now();
    if (Browser.nextRAF === 0) {
      Browser.nextRAF = now + 1e3 / 60;
    } else {
      while (now + 2 >= Browser.nextRAF) {
        Browser.nextRAF += 1e3 / 60;
      }
    }
    var delay = Math.max(Browser.nextRAF - now, 0);
    setTimeout(func, delay);
  },
  requestAnimationFrame: function requestAnimationFrame(func) {
    if (typeof window === "undefined") {
      Browser.fakeRequestAnimationFrame(func);
    } else {
      if (!window.requestAnimationFrame) {
        window.requestAnimationFrame =
          window["requestAnimationFrame"] ||
          window["mozRequestAnimationFrame"] ||
          window["webkitRequestAnimationFrame"] ||
          window["msRequestAnimationFrame"] ||
          window["oRequestAnimationFrame"] ||
          Browser.fakeRequestAnimationFrame;
      }
      window.requestAnimationFrame(func);
    }
  },
  safeCallback: function (func) {
    return function () {
      if (!ABORT) return func.apply(null, arguments);
    };
  },
  safeRequestAnimationFrame: function (func) {
    return Browser.requestAnimationFrame(function () {
      if (!ABORT) func();
    });
  },
  safeSetTimeout: function (func, timeout) {
    Module["noExitRuntime"] = true;
    return setTimeout(function () {
      if (!ABORT) func();
    }, timeout);
  },
  safeSetInterval: function (func, timeout) {
    Module["noExitRuntime"] = true;
    return setInterval(function () {
      if (!ABORT) func();
    }, timeout);
  },
  getMimetype: function (name) {
    return {
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      png: "image/png",
      bmp: "image/bmp",
      ogg: "audio/ogg",
      wav: "audio/wav",
      mp3: "audio/mpeg",
    }[name.substr(name.lastIndexOf(".") + 1)];
  },
  getUserMedia: function (func) {
    if (!window.getUserMedia) {
      window.getUserMedia =
        navigator["getUserMedia"] || navigator["mozGetUserMedia"];
    }
    window.getUserMedia(func);
  },
  getMovementX: function (event) {
    return (
      event["movementX"] ||
      event["mozMovementX"] ||
      event["webkitMovementX"] ||
      0
    );
  },
  getMovementY: function (event) {
    return (
      event["movementY"] ||
      event["mozMovementY"] ||
      event["webkitMovementY"] ||
      0
    );
  },
  getMouseWheelDelta: function (event) {
    var delta = 0;
    switch (event.type) {
      case "DOMMouseScroll":
        delta = event.detail;
        break;
      case "mousewheel":
        delta = event.wheelDelta;
        break;
      case "wheel":
        delta = event["deltaY"];
        break;
      default:
        throw "unrecognized mouse wheel event: " + event.type;
    }
    return delta;
  },
  mouseX: 0,
  mouseY: 0,
  mouseMovementX: 0,
  mouseMovementY: 0,
  touches: {},
  lastTouches: {},
  calculateMouseEvent: function (event) {
    if (Browser.pointerLock) {
      if (event.type != "mousemove" && "mozMovementX" in event) {
        Browser.mouseMovementX = Browser.mouseMovementY = 0;
      } else {
        Browser.mouseMovementX = Browser.getMovementX(event);
        Browser.mouseMovementY = Browser.getMovementY(event);
      }
      if (typeof SDL != "undefined") {
        Browser.mouseX = SDL.mouseX + Browser.mouseMovementX;
        Browser.mouseY = SDL.mouseY + Browser.mouseMovementY;
      } else {
        Browser.mouseX += Browser.mouseMovementX;
        Browser.mouseY += Browser.mouseMovementY;
      }
    } else {
      var rect = Module["canvas"].getBoundingClientRect();
      var cw = Module["canvas"].width;
      var ch = Module["canvas"].height;
      var scrollX =
        typeof window.scrollX !== "undefined"
          ? window.scrollX
          : window.pageXOffset;
      var scrollY =
        typeof window.scrollY !== "undefined"
          ? window.scrollY
          : window.pageYOffset;
      if (
        event.type === "touchstart" ||
        event.type === "touchend" ||
        event.type === "touchmove"
      ) {
        var touch = event.touch;
        if (touch === undefined) {
          return;
        }
        var adjustedX = touch.pageX - (scrollX + rect.left);
        var adjustedY = touch.pageY - (scrollY + rect.top);
        adjustedX = adjustedX * (cw / rect.width);
        adjustedY = adjustedY * (ch / rect.height);
        var coords = { x: adjustedX, y: adjustedY };
        if (event.type === "touchstart") {
          Browser.lastTouches[touch.identifier] = coords;
          Browser.touches[touch.identifier] = coords;
        } else if (event.type === "touchend" || event.type === "touchmove") {
          Browser.lastTouches[touch.identifier] =
            Browser.touches[touch.identifier];
          Browser.touches[touch.identifier] = { x: adjustedX, y: adjustedY };
        }
        return;
      }
      var x = event.pageX - (scrollX + rect.left);
      var y = event.pageY - (scrollY + rect.top);
      x = x * (cw / rect.width);
      y = y * (ch / rect.height);
      Browser.mouseMovementX = x - Browser.mouseX;
      Browser.mouseMovementY = y - Browser.mouseY;
      Browser.mouseX = x;
      Browser.mouseY = y;
    }
  },
  xhrLoad: function (url, onload, onerror) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url, true);
    xhr.responseType = "arraybuffer";
    xhr.onload = function xhr_onload() {
      if (xhr.status == 200 || (xhr.status == 0 && xhr.response)) {
        onload(xhr.response);
      } else {
        onerror();
      }
    };
    xhr.onerror = onerror;
    xhr.send(null);
  },
  asyncLoad: function (url, onload, onerror, noRunDep) {
    Browser.xhrLoad(
      url,
      function (arrayBuffer) {
        assert(
          arrayBuffer,
          'Loading data file "' + url + '" failed (no arrayBuffer).'
        );
        onload(new Uint8Array(arrayBuffer));
        if (!noRunDep) removeRunDependency("al " + url);
      },
      function (event) {
        if (onerror) {
          onerror();
        } else {
          throw 'Loading data file "' + url + '" failed.';
        }
      }
    );
    if (!noRunDep) addRunDependency("al " + url);
  },
  resizeListeners: [],
  updateResizeListeners: function () {
    var canvas = Module["canvas"];
    Browser.resizeListeners.forEach(function (listener) {
      listener(canvas.width, canvas.height);
    });
  },
  setCanvasSize: function (width, height, noUpdates) {
    var canvas = Module["canvas"];
    Browser.updateCanvasDimensions(canvas, width, height);
    if (!noUpdates) Browser.updateResizeListeners();
  },
  windowedWidth: 0,
  windowedHeight: 0,
  setFullScreenCanvasSize: function () {
    if (typeof SDL != "undefined") {
      var flags = HEAPU32[(SDL.screen + Runtime.QUANTUM_SIZE * 0) >> 2];
      flags = flags | 8388608;
      HEAP32[(SDL.screen + Runtime.QUANTUM_SIZE * 0) >> 2] = flags;
    }
    Browser.updateResizeListeners();
  },
  setWindowedCanvasSize: function () {
    if (typeof SDL != "undefined") {
      var flags = HEAPU32[(SDL.screen + Runtime.QUANTUM_SIZE * 0) >> 2];
      flags = flags & ~8388608;
      HEAP32[(SDL.screen + Runtime.QUANTUM_SIZE * 0) >> 2] = flags;
    }
    Browser.updateResizeListeners();
  },
  updateCanvasDimensions: function (canvas, wNative, hNative) {
    if (wNative && hNative) {
      canvas.widthNative = wNative;
      canvas.heightNative = hNative;
    } else {
      wNative = canvas.widthNative;
      hNative = canvas.heightNative;
    }
    var w = wNative;
    var h = hNative;
    if (Module["forcedAspectRatio"] && Module["forcedAspectRatio"] > 0) {
      if (w / h < Module["forcedAspectRatio"]) {
        w = Math.round(h * Module["forcedAspectRatio"]);
      } else {
        h = Math.round(w / Module["forcedAspectRatio"]);
      }
    }
    if (
      (document["webkitFullScreenElement"] ||
        document["webkitFullscreenElement"] ||
        document["mozFullScreenElement"] ||
        document["mozFullscreenElement"] ||
        document["fullScreenElement"] ||
        document["fullscreenElement"] ||
        document["msFullScreenElement"] ||
        document["msFullscreenElement"] ||
        document["webkitCurrentFullScreenElement"]) === canvas.parentNode &&
      typeof screen != "undefined"
    ) {
      var factor = Math.min(screen.width / w, screen.height / h);
      w = Math.round(w * factor);
      h = Math.round(h * factor);
    }
    if (Browser.resizeCanvas) {
      if (canvas.width != w) canvas.width = w;
      if (canvas.height != h) canvas.height = h;
      if (typeof canvas.style != "undefined") {
        canvas.style.removeProperty("width");
        canvas.style.removeProperty("height");
      }
    } else {
      if (canvas.width != wNative) canvas.width = wNative;
      if (canvas.height != hNative) canvas.height = hNative;
      if (typeof canvas.style != "undefined") {
        if (w != wNative || h != hNative) {
          canvas.style.setProperty("width", w + "px", "important");
          canvas.style.setProperty("height", h + "px", "important");
        } else {
          canvas.style.removeProperty("width");
          canvas.style.removeProperty("height");
        }
      }
    }
  },
  wgetRequests: {},
  nextWgetRequestHandle: 0,
  getNextWgetRequestHandle: function () {
    var handle = Browser.nextWgetRequestHandle;
    Browser.nextWgetRequestHandle++;
    return handle;
  },
};
function _sbrk(bytes) {
  var self = _sbrk;
  if (!self.called) {
    DYNAMICTOP = alignMemoryPage(DYNAMICTOP);
    self.called = true;
    assert(Runtime.dynamicAlloc);
    self.alloc = Runtime.dynamicAlloc;
    Runtime.dynamicAlloc = function () {
      abort("cannot dynamically allocate, sbrk now has control");
    };
  }
  var ret = DYNAMICTOP;
  if (bytes != 0) self.alloc(bytes);
  return ret;
}
function _time(ptr) {
  var ret = (Date.now() / 1e3) | 0;
  if (ptr) {
    HEAP32[ptr >> 2] = ret;
  }
  return ret;
}
function _mkport() {
  throw "TODO";
}
var SOCKFS = {
  mount: function (mount) {
    Module["websocket"] =
      Module["websocket"] && "object" === typeof Module["websocket"]
        ? Module["websocket"]
        : {};
    Module["websocket"]._callbacks = {};
    Module["websocket"]["on"] = function (event, callback) {
      if ("function" === typeof callback) {
        this._callbacks[event] = callback;
      }
      return this;
    };
    Module["websocket"].emit = function (event, param) {
      if ("function" === typeof this._callbacks[event]) {
        this._callbacks[event].call(this, param);
      }
    };
    return FS.createNode(null, "/", 16384 | 511, 0);
  },
  createSocket: function (family, type, protocol) {
    var streaming = type == 1;
    if (protocol) {
      assert(streaming == (protocol == 6));
    }
    var sock = {
      family: family,
      type: type,
      protocol: protocol,
      server: null,
      error: null,
      peers: {},
      pending: [],
      recv_queue: [],
      sock_ops: SOCKFS.websocket_sock_ops,
    };
    var name = SOCKFS.nextname();
    var node = FS.createNode(SOCKFS.root, name, 49152, 0);
    node.sock = sock;
    var stream = FS.createStream({
      path: name,
      node: node,
      flags: FS.modeStringToFlags("r+"),
      seekable: false,
      stream_ops: SOCKFS.stream_ops,
    });
    sock.stream = stream;
    return sock;
  },
  getSocket: function (fd) {
    var stream = FS.getStream(fd);
    if (!stream || !FS.isSocket(stream.node.mode)) {
      return null;
    }
    return stream.node.sock;
  },
  stream_ops: {
    poll: function (stream) {
      var sock = stream.node.sock;
      return sock.sock_ops.poll(sock);
    },
    ioctl: function (stream, request, varargs) {
      var sock = stream.node.sock;
      return sock.sock_ops.ioctl(sock, request, varargs);
    },
    read: function (stream, buffer, offset, length, position) {
      var sock = stream.node.sock;
      var msg = sock.sock_ops.recvmsg(sock, length);
      if (!msg) {
        return 0;
      }
      buffer.set(msg.buffer, offset);
      return msg.buffer.length;
    },
    write: function (stream, buffer, offset, length, position) {
      var sock = stream.node.sock;
      return sock.sock_ops.sendmsg(sock, buffer, offset, length);
    },
    close: function (stream) {
      var sock = stream.node.sock;
      sock.sock_ops.close(sock);
    },
  },
  nextname: function () {
    if (!SOCKFS.nextname.current) {
      SOCKFS.nextname.current = 0;
    }
    return "socket[" + SOCKFS.nextname.current++ + "]";
  },
  websocket_sock_ops: {
    createPeer: function (sock, addr, port) {
      var ws;
      if (typeof addr === "object") {
        ws = addr;
        addr = null;
        port = null;
      }
      if (ws) {
        if (ws._socket) {
          addr = ws._socket.remoteAddress;
          port = ws._socket.remotePort;
        } else {
          var result = /ws[s]?:\/\/([^:]+):(\d+)/.exec(ws.url);
          if (!result) {
            throw new Error(
              "WebSocket URL must be in the format ws(s)://address:port"
            );
          }
          addr = result[1];
          port = parseInt(result[2], 10);
        }
      } else {
        try {
          var runtimeConfig =
            Module["websocket"] && "object" === typeof Module["websocket"];
          var url = "ws:#".replace("#", "//");
          if (runtimeConfig) {
            if ("string" === typeof Module["websocket"]["url"]) {
              url = Module["websocket"]["url"];
            }
          }
          if (url === "ws://" || url === "wss://") {
            var parts = addr.split("/");
            url = url + parts[0] + ":" + port + "/" + parts.slice(1).join("/");
          }
          var subProtocols = "binary";
          if (runtimeConfig) {
            if ("string" === typeof Module["websocket"]["subprotocol"]) {
              subProtocols = Module["websocket"]["subprotocol"];
            }
          }
          subProtocols = subProtocols.replace(/^ +| +$/g, "").split(/ *, */);
          var opts = ENVIRONMENT_IS_NODE
            ? { protocol: subProtocols.toString() }
            : subProtocols;
          var WebSocket = ENVIRONMENT_IS_NODE
            ? require("ws")
            : window["WebSocket"];
          ws = new WebSocket(url, opts);
          ws.binaryType = "arraybuffer";
        } catch (e) {
          throw new FS.ErrnoError(ERRNO_CODES.EHOSTUNREACH);
        }
      }
      var peer = { addr: addr, port: port, socket: ws, dgram_send_queue: [] };
      SOCKFS.websocket_sock_ops.addPeer(sock, peer);
      SOCKFS.websocket_sock_ops.handlePeerEvents(sock, peer);
      if (sock.type === 2 && typeof sock.sport !== "undefined") {
        peer.dgram_send_queue.push(
          new Uint8Array([
            255,
            255,
            255,
            255,
            "p".charCodeAt(0),
            "o".charCodeAt(0),
            "r".charCodeAt(0),
            "t".charCodeAt(0),
            (sock.sport & 65280) >> 8,
            sock.sport & 255,
          ])
        );
      }
      return peer;
    },
    getPeer: function (sock, addr, port) {
      return sock.peers[addr + ":" + port];
    },
    addPeer: function (sock, peer) {
      sock.peers[peer.addr + ":" + peer.port] = peer;
    },
    removePeer: function (sock, peer) {
      delete sock.peers[peer.addr + ":" + peer.port];
    },
    handlePeerEvents: function (sock, peer) {
      var first = true;
      var handleOpen = function () {
        Module["websocket"].emit("open", sock.stream.fd);
        try {
          var queued = peer.dgram_send_queue.shift();
          while (queued) {
            peer.socket.send(queued);
            queued = peer.dgram_send_queue.shift();
          }
        } catch (e) {
          peer.socket.close();
        }
      };
      function handleMessage(data) {
        assert(typeof data !== "string" && data.byteLength !== undefined);
        data = new Uint8Array(data);
        var wasfirst = first;
        first = false;
        if (
          wasfirst &&
          data.length === 10 &&
          data[0] === 255 &&
          data[1] === 255 &&
          data[2] === 255 &&
          data[3] === 255 &&
          data[4] === "p".charCodeAt(0) &&
          data[5] === "o".charCodeAt(0) &&
          data[6] === "r".charCodeAt(0) &&
          data[7] === "t".charCodeAt(0)
        ) {
          var newport = (data[8] << 8) | data[9];
          SOCKFS.websocket_sock_ops.removePeer(sock, peer);
          peer.port = newport;
          SOCKFS.websocket_sock_ops.addPeer(sock, peer);
          return;
        }
        sock.recv_queue.push({ addr: peer.addr, port: peer.port, data: data });
        Module["websocket"].emit("message", sock.stream.fd);
      }
      if (ENVIRONMENT_IS_NODE) {
        peer.socket.on("open", handleOpen);
        peer.socket.on("message", function (data, flags) {
          if (!flags.binary) {
            return;
          }
          handleMessage(new Uint8Array(data).buffer);
        });
        peer.socket.on("close", function () {
          Module["websocket"].emit("close", sock.stream.fd);
        });
        peer.socket.on("error", function (error) {
          sock.error = ERRNO_CODES.ECONNREFUSED;
          Module["websocket"].emit("error", [
            sock.stream.fd,
            sock.error,
            "ECONNREFUSED: Connection refused",
          ]);
        });
      } else {
        peer.socket.onopen = handleOpen;
        peer.socket.onclose = function () {
          Module["websocket"].emit("close", sock.stream.fd);
        };
        peer.socket.onmessage = function peer_socket_onmessage(event) {
          handleMessage(event.data);
        };
        peer.socket.onerror = function (error) {
          sock.error = ERRNO_CODES.ECONNREFUSED;
          Module["websocket"].emit("error", [
            sock.stream.fd,
            sock.error,
            "ECONNREFUSED: Connection refused",
          ]);
        };
      }
    },
    poll: function (sock) {
      if (sock.type === 1 && sock.server) {
        return sock.pending.length ? 64 | 1 : 0;
      }
      var mask = 0;
      var dest =
        sock.type === 1
          ? SOCKFS.websocket_sock_ops.getPeer(sock, sock.daddr, sock.dport)
          : null;
      if (
        sock.recv_queue.length ||
        !dest ||
        (dest && dest.socket.readyState === dest.socket.CLOSING) ||
        (dest && dest.socket.readyState === dest.socket.CLOSED)
      ) {
        mask |= 64 | 1;
      }
      if (!dest || (dest && dest.socket.readyState === dest.socket.OPEN)) {
        mask |= 4;
      }
      if (
        (dest && dest.socket.readyState === dest.socket.CLOSING) ||
        (dest && dest.socket.readyState === dest.socket.CLOSED)
      ) {
        mask |= 16;
      }
      return mask;
    },
    ioctl: function (sock, request, arg) {
      switch (request) {
        case 21531:
          var bytes = 0;
          if (sock.recv_queue.length) {
            bytes = sock.recv_queue[0].data.length;
          }
          HEAP32[arg >> 2] = bytes;
          return 0;
        default:
          return ERRNO_CODES.EINVAL;
      }
    },
    close: function (sock) {
      if (sock.server) {
        try {
          sock.server.close();
        } catch (e) {}
        sock.server = null;
      }
      var peers = Object.keys(sock.peers);
      for (var i = 0; i < peers.length; i++) {
        var peer = sock.peers[peers[i]];
        try {
          peer.socket.close();
        } catch (e) {}
        SOCKFS.websocket_sock_ops.removePeer(sock, peer);
      }
      return 0;
    },
    bind: function (sock, addr, port) {
      if (
        typeof sock.saddr !== "undefined" ||
        typeof sock.sport !== "undefined"
      ) {
        throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
      }
      sock.saddr = addr;
      sock.sport = port || _mkport();
      if (sock.type === 2) {
        if (sock.server) {
          sock.server.close();
          sock.server = null;
        }
        try {
          sock.sock_ops.listen(sock, 0);
        } catch (e) {
          if (!(e instanceof FS.ErrnoError)) throw e;
          if (e.errno !== ERRNO_CODES.EOPNOTSUPP) throw e;
        }
      }
    },
    connect: function (sock, addr, port) {
      if (sock.server) {
        throw new FS.ErrnoError(ERRNO_CODES.EOPNOTSUPP);
      }
      if (
        typeof sock.daddr !== "undefined" &&
        typeof sock.dport !== "undefined"
      ) {
        var dest = SOCKFS.websocket_sock_ops.getPeer(
          sock,
          sock.daddr,
          sock.dport
        );
        if (dest) {
          if (dest.socket.readyState === dest.socket.CONNECTING) {
            throw new FS.ErrnoError(ERRNO_CODES.EALREADY);
          } else {
            throw new FS.ErrnoError(ERRNO_CODES.EISCONN);
          }
        }
      }
      var peer = SOCKFS.websocket_sock_ops.createPeer(sock, addr, port);
      sock.daddr = peer.addr;
      sock.dport = peer.port;
      throw new FS.ErrnoError(ERRNO_CODES.EINPROGRESS);
    },
    listen: function (sock, backlog) {
      if (!ENVIRONMENT_IS_NODE) {
        throw new FS.ErrnoError(ERRNO_CODES.EOPNOTSUPP);
      }
      if (sock.server) {
        throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
      }
      var WebSocketServer = require("ws").Server;
      var host = sock.saddr;
      sock.server = new WebSocketServer({ host: host, port: sock.sport });
      Module["websocket"].emit("listen", sock.stream.fd);
      sock.server.on("connection", function (ws) {
        if (sock.type === 1) {
          var newsock = SOCKFS.createSocket(
            sock.family,
            sock.type,
            sock.protocol
          );
          var peer = SOCKFS.websocket_sock_ops.createPeer(newsock, ws);
          newsock.daddr = peer.addr;
          newsock.dport = peer.port;
          sock.pending.push(newsock);
          Module["websocket"].emit("connection", newsock.stream.fd);
        } else {
          SOCKFS.websocket_sock_ops.createPeer(sock, ws);
          Module["websocket"].emit("connection", sock.stream.fd);
        }
      });
      sock.server.on("closed", function () {
        Module["websocket"].emit("close", sock.stream.fd);
        sock.server = null;
      });
      sock.server.on("error", function (error) {
        sock.error = ERRNO_CODES.EHOSTUNREACH;
        Module["websocket"].emit("error", [
          sock.stream.fd,
          sock.error,
          "EHOSTUNREACH: Host is unreachable",
        ]);
      });
    },
    accept: function (listensock) {
      if (!listensock.server) {
        throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
      }
      var newsock = listensock.pending.shift();
      newsock.stream.flags = listensock.stream.flags;
      return newsock;
    },
    getname: function (sock, peer) {
      var addr, port;
      if (peer) {
        if (sock.daddr === undefined || sock.dport === undefined) {
          throw new FS.ErrnoError(ERRNO_CODES.ENOTCONN);
        }
        addr = sock.daddr;
        port = sock.dport;
      } else {
        addr = sock.saddr || 0;
        port = sock.sport || 0;
      }
      return { addr: addr, port: port };
    },
    sendmsg: function (sock, buffer, offset, length, addr, port) {
      if (sock.type === 2) {
        if (addr === undefined || port === undefined) {
          addr = sock.daddr;
          port = sock.dport;
        }
        if (addr === undefined || port === undefined) {
          throw new FS.ErrnoError(ERRNO_CODES.EDESTADDRREQ);
        }
      } else {
        addr = sock.daddr;
        port = sock.dport;
      }
      var dest = SOCKFS.websocket_sock_ops.getPeer(sock, addr, port);
      if (sock.type === 1) {
        if (
          !dest ||
          dest.socket.readyState === dest.socket.CLOSING ||
          dest.socket.readyState === dest.socket.CLOSED
        ) {
          throw new FS.ErrnoError(ERRNO_CODES.ENOTCONN);
        } else if (dest.socket.readyState === dest.socket.CONNECTING) {
          throw new FS.ErrnoError(ERRNO_CODES.EAGAIN);
        }
      }
      var data;
      if (buffer instanceof Array || buffer instanceof ArrayBuffer) {
        data = buffer.slice(offset, offset + length);
      } else {
        data = buffer.buffer.slice(
          buffer.byteOffset + offset,
          buffer.byteOffset + offset + length
        );
      }
      if (sock.type === 2) {
        if (!dest || dest.socket.readyState !== dest.socket.OPEN) {
          if (
            !dest ||
            dest.socket.readyState === dest.socket.CLOSING ||
            dest.socket.readyState === dest.socket.CLOSED
          ) {
            dest = SOCKFS.websocket_sock_ops.createPeer(sock, addr, port);
          }
          dest.dgram_send_queue.push(data);
          return length;
        }
      }
      try {
        dest.socket.send(data);
        return length;
      } catch (e) {
        throw new FS.ErrnoError(ERRNO_CODES.EINVAL);
      }
    },
    recvmsg: function (sock, length) {
      if (sock.type === 1 && sock.server) {
        throw new FS.ErrnoError(ERRNO_CODES.ENOTCONN);
      }
      var queued = sock.recv_queue.shift();
      if (!queued) {
        if (sock.type === 1) {
          var dest = SOCKFS.websocket_sock_ops.getPeer(
            sock,
            sock.daddr,
            sock.dport
          );
          if (!dest) {
            throw new FS.ErrnoError(ERRNO_CODES.ENOTCONN);
          } else if (
            dest.socket.readyState === dest.socket.CLOSING ||
            dest.socket.readyState === dest.socket.CLOSED
          ) {
            return null;
          } else {
            throw new FS.ErrnoError(ERRNO_CODES.EAGAIN);
          }
        } else {
          throw new FS.ErrnoError(ERRNO_CODES.EAGAIN);
        }
      }
      var queuedLength = queued.data.byteLength || queued.data.length;
      var queuedOffset = queued.data.byteOffset || 0;
      var queuedBuffer = queued.data.buffer || queued.data;
      var bytesRead = Math.min(length, queuedLength);
      var res = {
        buffer: new Uint8Array(queuedBuffer, queuedOffset, bytesRead),
        addr: queued.addr,
        port: queued.port,
      };
      if (sock.type === 1 && bytesRead < queuedLength) {
        var bytesRemaining = queuedLength - bytesRead;
        queued.data = new Uint8Array(
          queuedBuffer,
          queuedOffset + bytesRead,
          bytesRemaining
        );
        sock.recv_queue.unshift(queued);
      }
      return res;
    },
  },
};
function _send(fd, buf, len, flags) {
  var sock = SOCKFS.getSocket(fd);
  if (!sock) {
    ___setErrNo(ERRNO_CODES.EBADF);
    return -1;
  }
  return _write(fd, buf, len);
}
function _pwrite(fildes, buf, nbyte, offset) {
  var stream = FS.getStream(fildes);
  if (!stream) {
    ___setErrNo(ERRNO_CODES.EBADF);
    return -1;
  }
  try {
    var slab = HEAP8;
    return FS.write(stream, slab, buf, nbyte, offset);
  } catch (e) {
    FS.handleFSError(e);
    return -1;
  }
}
function _write(fildes, buf, nbyte) {
  var stream = FS.getStream(fildes);
  if (!stream) {
    ___setErrNo(ERRNO_CODES.EBADF);
    return -1;
  }
  try {
    var slab = HEAP8;
    return FS.write(stream, slab, buf, nbyte);
  } catch (e) {
    FS.handleFSError(e);
    return -1;
  }
}
function _fileno(stream) {
  stream = FS.getStreamFromPtr(stream);
  if (!stream) return -1;
  return stream.fd;
}
function _fwrite(ptr, size, nitems, stream) {
  var bytesToWrite = nitems * size;
  if (bytesToWrite == 0) return 0;
  var fd = _fileno(stream);
  var bytesWritten = _write(fd, ptr, bytesToWrite);
  if (bytesWritten == -1) {
    var streamObj = FS.getStreamFromPtr(stream);
    if (streamObj) streamObj.error = true;
    return 0;
  } else {
    return (bytesWritten / size) | 0;
  }
}
Module["_strlen"] = _strlen;
function __reallyNegative(x) {
  return x < 0 || (x === 0 && 1 / x === -Infinity);
}
function __formatString(format, varargs) {
  var textIndex = format;
  var argIndex = 0;
  function getNextArg(type) {
    var ret;
    if (type === "double") {
      ret =
        ((HEAP32[tempDoublePtr >> 2] = HEAP32[(varargs + argIndex) >> 2]),
        (HEAP32[(tempDoublePtr + 4) >> 2] =
          HEAP32[(varargs + (argIndex + 4)) >> 2]),
        +HEAPF64[tempDoublePtr >> 3]);
    } else if (type == "i64") {
      ret = [
        HEAP32[(varargs + argIndex) >> 2],
        HEAP32[(varargs + (argIndex + 4)) >> 2],
      ];
    } else {
      type = "i32";
      ret = HEAP32[(varargs + argIndex) >> 2];
    }
    argIndex += Runtime.getNativeFieldSize(type);
    return ret;
  }
  var ret = [];
  var curr, next, currArg;
  while (1) {
    var startTextIndex = textIndex;
    curr = HEAP8[textIndex >> 0];
    if (curr === 0) break;
    next = HEAP8[(textIndex + 1) >> 0];
    if (curr == 37) {
      var flagAlwaysSigned = false;
      var flagLeftAlign = false;
      var flagAlternative = false;
      var flagZeroPad = false;
      var flagPadSign = false;
      flagsLoop: while (1) {
        switch (next) {
          case 43:
            flagAlwaysSigned = true;
            break;
          case 45:
            flagLeftAlign = true;
            break;
          case 35:
            flagAlternative = true;
            break;
          case 48:
            if (flagZeroPad) {
              break flagsLoop;
            } else {
              flagZeroPad = true;
              break;
            }
          case 32:
            flagPadSign = true;
            break;
          default:
            break flagsLoop;
        }
        textIndex++;
        next = HEAP8[(textIndex + 1) >> 0];
      }
      var width = 0;
      if (next == 42) {
        width = getNextArg("i32");
        textIndex++;
        next = HEAP8[(textIndex + 1) >> 0];
      } else {
        while (next >= 48 && next <= 57) {
          width = width * 10 + (next - 48);
          textIndex++;
          next = HEAP8[(textIndex + 1) >> 0];
        }
      }
      var precisionSet = false,
        precision = -1;
      if (next == 46) {
        precision = 0;
        precisionSet = true;
        textIndex++;
        next = HEAP8[(textIndex + 1) >> 0];
        if (next == 42) {
          precision = getNextArg("i32");
          textIndex++;
        } else {
          while (1) {
            var precisionChr = HEAP8[(textIndex + 1) >> 0];
            if (precisionChr < 48 || precisionChr > 57) break;
            precision = precision * 10 + (precisionChr - 48);
            textIndex++;
          }
        }
        next = HEAP8[(textIndex + 1) >> 0];
      }
      if (precision < 0) {
        precision = 6;
        precisionSet = false;
      }
      var argSize;
      switch (String.fromCharCode(next)) {
        case "h":
          var nextNext = HEAP8[(textIndex + 2) >> 0];
          if (nextNext == 104) {
            textIndex++;
            argSize = 1;
          } else {
            argSize = 2;
          }
          break;
        case "l":
          var nextNext = HEAP8[(textIndex + 2) >> 0];
          if (nextNext == 108) {
            textIndex++;
            argSize = 8;
          } else {
            argSize = 4;
          }
          break;
        case "L":
        case "q":
        case "j":
          argSize = 8;
          break;
        case "z":
        case "t":
        case "I":
          argSize = 4;
          break;
        default:
          argSize = null;
      }
      if (argSize) textIndex++;
      next = HEAP8[(textIndex + 1) >> 0];
      switch (String.fromCharCode(next)) {
        case "d":
        case "i":
        case "u":
        case "o":
        case "x":
        case "X":
        case "p": {
          var signed = next == 100 || next == 105;
          argSize = argSize || 4;
          var currArg = getNextArg("i" + argSize * 8);
          var origArg = currArg;
          var argText;
          if (argSize == 8) {
            currArg = Runtime.makeBigInt(currArg[0], currArg[1], next == 117);
          }
          if (argSize <= 4) {
            var limit = Math.pow(256, argSize) - 1;
            currArg = (signed ? reSign : unSign)(currArg & limit, argSize * 8);
          }
          var currAbsArg = Math.abs(currArg);
          var prefix = "";
          if (next == 100 || next == 105) {
            if (argSize == 8 && i64Math)
              argText = i64Math.stringify(origArg[0], origArg[1], null);
            else argText = reSign(currArg, 8 * argSize, 1).toString(10);
          } else if (next == 117) {
            if (argSize == 8 && i64Math)
              argText = i64Math.stringify(origArg[0], origArg[1], true);
            else argText = unSign(currArg, 8 * argSize, 1).toString(10);
            currArg = Math.abs(currArg);
          } else if (next == 111) {
            argText = (flagAlternative ? "0" : "") + currAbsArg.toString(8);
          } else if (next == 120 || next == 88) {
            prefix = flagAlternative && currArg != 0 ? "0x" : "";
            if (argSize == 8 && i64Math) {
              if (origArg[1]) {
                argText = (origArg[1] >>> 0).toString(16);
                var lower = (origArg[0] >>> 0).toString(16);
                while (lower.length < 8) lower = "0" + lower;
                argText += lower;
              } else {
                argText = (origArg[0] >>> 0).toString(16);
              }
            } else if (currArg < 0) {
              currArg = -currArg;
              argText = (currAbsArg - 1).toString(16);
              var buffer = [];
              for (var i = 0; i < argText.length; i++) {
                buffer.push((15 - parseInt(argText[i], 16)).toString(16));
              }
              argText = buffer.join("");
              while (argText.length < argSize * 2) argText = "f" + argText;
            } else {
              argText = currAbsArg.toString(16);
            }
            if (next == 88) {
              prefix = prefix.toUpperCase();
              argText = argText.toUpperCase();
            }
          } else if (next == 112) {
            if (currAbsArg === 0) {
              argText = "(nil)";
            } else {
              prefix = "0x";
              argText = currAbsArg.toString(16);
            }
          }
          if (precisionSet) {
            while (argText.length < precision) {
              argText = "0" + argText;
            }
          }
          if (currArg >= 0) {
            if (flagAlwaysSigned) {
              prefix = "+" + prefix;
            } else if (flagPadSign) {
              prefix = " " + prefix;
            }
          }
          if (argText.charAt(0) == "-") {
            prefix = "-" + prefix;
            argText = argText.substr(1);
          }
          while (prefix.length + argText.length < width) {
            if (flagLeftAlign) {
              argText += " ";
            } else {
              if (flagZeroPad) {
                argText = "0" + argText;
              } else {
                prefix = " " + prefix;
              }
            }
          }
          argText = prefix + argText;
          argText.split("").forEach(function (chr) {
            ret.push(chr.charCodeAt(0));
          });
          break;
        }
        case "f":
        case "F":
        case "e":
        case "E":
        case "g":
        case "G": {
          var currArg = getNextArg("double");
          var argText;
          if (isNaN(currArg)) {
            argText = "nan";
            flagZeroPad = false;
          } else if (!isFinite(currArg)) {
            argText = (currArg < 0 ? "-" : "") + "inf";
            flagZeroPad = false;
          } else {
            var isGeneral = false;
            var effectivePrecision = Math.min(precision, 20);
            if (next == 103 || next == 71) {
              isGeneral = true;
              precision = precision || 1;
              var exponent = parseInt(
                currArg.toExponential(effectivePrecision).split("e")[1],
                10
              );
              if (precision > exponent && exponent >= -4) {
                next = (next == 103 ? "f" : "F").charCodeAt(0);
                precision -= exponent + 1;
              } else {
                next = (next == 103 ? "e" : "E").charCodeAt(0);
                precision--;
              }
              effectivePrecision = Math.min(precision, 20);
            }
            if (next == 101 || next == 69) {
              argText = currArg.toExponential(effectivePrecision);
              if (/[eE][-+]\d$/.test(argText)) {
                argText = argText.slice(0, -1) + "0" + argText.slice(-1);
              }
            } else if (next == 102 || next == 70) {
              argText = currArg.toFixed(effectivePrecision);
              if (currArg === 0 && __reallyNegative(currArg)) {
                argText = "-" + argText;
              }
            }
            var parts = argText.split("e");
            if (isGeneral && !flagAlternative) {
              while (
                parts[0].length > 1 &&
                parts[0].indexOf(".") != -1 &&
                (parts[0].slice(-1) == "0" || parts[0].slice(-1) == ".")
              ) {
                parts[0] = parts[0].slice(0, -1);
              }
            } else {
              if (flagAlternative && argText.indexOf(".") == -1)
                parts[0] += ".";
              while (precision > effectivePrecision++) parts[0] += "0";
            }
            argText = parts[0] + (parts.length > 1 ? "e" + parts[1] : "");
            if (next == 69) argText = argText.toUpperCase();
            if (currArg >= 0) {
              if (flagAlwaysSigned) {
                argText = "+" + argText;
              } else if (flagPadSign) {
                argText = " " + argText;
              }
            }
          }
          while (argText.length < width) {
            if (flagLeftAlign) {
              argText += " ";
            } else {
              if (flagZeroPad && (argText[0] == "-" || argText[0] == "+")) {
                argText = argText[0] + "0" + argText.slice(1);
              } else {
                argText = (flagZeroPad ? "0" : " ") + argText;
              }
            }
          }
          if (next < 97) argText = argText.toUpperCase();
          argText.split("").forEach(function (chr) {
            ret.push(chr.charCodeAt(0));
          });
          break;
        }
        case "s": {
          var arg = getNextArg("i8*");
          var argLength = arg ? _strlen(arg) : "(null)".length;
          if (precisionSet) argLength = Math.min(argLength, precision);
          if (!flagLeftAlign) {
            while (argLength < width--) {
              ret.push(32);
            }
          }
          if (arg) {
            for (var i = 0; i < argLength; i++) {
              ret.push(HEAPU8[arg++ >> 0]);
            }
          } else {
            ret = ret.concat(
              intArrayFromString("(null)".substr(0, argLength), true)
            );
          }
          if (flagLeftAlign) {
            while (argLength < width--) {
              ret.push(32);
            }
          }
          break;
        }
        case "c": {
          if (flagLeftAlign) ret.push(getNextArg("i8"));
          while (--width > 0) {
            ret.push(32);
          }
          if (!flagLeftAlign) ret.push(getNextArg("i8"));
          break;
        }
        case "n": {
          var ptr = getNextArg("i32*");
          HEAP32[ptr >> 2] = ret.length;
          break;
        }
        case "%": {
          ret.push(curr);
          break;
        }
        default: {
          for (var i = startTextIndex; i < textIndex + 2; i++) {
            ret.push(HEAP8[i >> 0]);
          }
        }
      }
      textIndex += 2;
    } else {
      ret.push(curr);
      textIndex += 1;
    }
  }
  return ret;
}
function _fprintf(stream, format, varargs) {
  var result = __formatString(format, varargs);
  var stack = Runtime.stackSave();
  var ret = _fwrite(
    allocate(result, "i8", ALLOC_STACK),
    1,
    result.length,
    stream
  );
  Runtime.stackRestore(stack);
  return ret;
}
function _emscripten_memcpy_big(dest, src, num) {
  HEAPU8.set(HEAPU8.subarray(src, src + num), dest);
  return dest;
}
Module["_memcpy"] = _memcpy;
___errno_state = Runtime.staticAlloc(4);
HEAP32[___errno_state >> 2] = 0;
Module["requestFullScreen"] = function Module_requestFullScreen(
  lockPointer,
  resizeCanvas
) {
  Browser.requestFullScreen(lockPointer, resizeCanvas);
};
Module["requestAnimationFrame"] = function Module_requestAnimationFrame(func) {
  Browser.requestAnimationFrame(func);
};
Module["setCanvasSize"] = function Module_setCanvasSize(
  width,
  height,
  noUpdates
) {
  Browser.setCanvasSize(width, height, noUpdates);
};
Module["pauseMainLoop"] = function Module_pauseMainLoop() {
  Browser.mainLoop.pause();
};
Module["resumeMainLoop"] = function Module_resumeMainLoop() {
  Browser.mainLoop.resume();
};
Module["getUserMedia"] = function Module_getUserMedia() {
  Browser.getUserMedia();
};
FS.staticInit();
__ATINIT__.unshift({
  func: function () {
    if (!Module["noFSInit"] && !FS.init.initialized) FS.init();
  },
});
__ATMAIN__.push({
  func: function () {
    FS.ignorePermissions = false;
  },
});
__ATEXIT__.push({
  func: function () {
    FS.quit();
  },
});
Module["FS_createFolder"] = FS.createFolder;
Module["FS_createPath"] = FS.createPath;
Module["FS_createDataFile"] = FS.createDataFile;
Module["FS_createPreloadedFile"] = FS.createPreloadedFile;
Module["FS_createLazyFile"] = FS.createLazyFile;
Module["FS_createLink"] = FS.createLink;
Module["FS_createDevice"] = FS.createDevice;
__ATINIT__.unshift({
  func: function () {
    TTY.init();
  },
});
__ATEXIT__.push({
  func: function () {
    TTY.shutdown();
  },
});
TTY.utf8 = new Runtime.UTF8Processor();
if (ENVIRONMENT_IS_NODE) {
  var fs = require("test/test/node_modules/fs");
  NODEFS.staticInit();
}
__ATINIT__.push({
  func: function () {
    SOCKFS.root = FS.mount(SOCKFS, {}, null);
  },
});
STACK_BASE = STACKTOP = Runtime.alignMemory(STATICTOP);
staticSealed = true;
STACK_MAX = STACK_BASE + TOTAL_STACK;
DYNAMIC_BASE = DYNAMICTOP = Runtime.alignMemory(STACK_MAX);
assert(DYNAMIC_BASE < TOTAL_MEMORY, "TOTAL_MEMORY not big enough for stack");
var ctlz_i8 = allocate(
  [
    8,
    7,
    6,
    6,
    5,
    5,
    5,
    5,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    3,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    2,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
  ],
  "i8",
  ALLOC_DYNAMIC
);
var cttz_i8 = allocate(
  [
    8,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    5,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    6,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    5,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    7,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    5,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    6,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    5,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    4,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
    3,
    0,
    1,
    0,
    2,
    0,
    1,
    0,
  ],
  "i8",
  ALLOC_DYNAMIC
);
function invoke_iiiiii(index, a1, a2, a3, a4, a5) {
  try {
    return Module["dynCall_iiiiii"](index, a1, a2, a3, a4, a5);
  } catch (e) {
    if (typeof e !== "number" && e !== "longjmp") throw e;
    asm["setThrew"](1, 0);
  }
}
Module.asmGlobalArg = {
  Math: Math,
  Int8Array: Int8Array,
  Int16Array: Int16Array,
  Int32Array: Int32Array,
  Uint8Array: Uint8Array,
  Uint16Array: Uint16Array,
  Uint32Array: Uint32Array,
  Float32Array: Float32Array,
  Float64Array: Float64Array,
};
Module.asmLibraryArg = {
  abort: abort,
  assert: assert,
  min: Math_min,
  invoke_iiiiii: invoke_iiiiii,
  _fflush: _fflush,
  __formatString: __formatString,
  _time: _time,
  _send: _send,
  _pwrite: _pwrite,
  _emscripten_set_main_loop: _emscripten_set_main_loop,
  _abort: _abort,
  __reallyNegative: __reallyNegative,
  _fwrite: _fwrite,
  _sbrk: _sbrk,
  _mkport: _mkport,
  _fprintf: _fprintf,
  ___setErrNo: ___setErrNo,
  _emscripten_memcpy_big: _emscripten_memcpy_big,
  _fileno: _fileno,
  _write: _write,
  _emscripten_set_main_loop_timing: _emscripten_set_main_loop_timing,
  _sysconf: _sysconf,
  ___errno_location: ___errno_location,
  STACKTOP: STACKTOP,
  STACK_MAX: STACK_MAX,
  tempDoublePtr: tempDoublePtr,
  ABORT: ABORT,
  cttz_i8: cttz_i8,
  ctlz_i8: ctlz_i8,
  NaN: NaN,
  Infinity: Infinity,
  _stderr: _stderr,
}; // EMSCRIPTEN_START_ASM
var asm = (function (global, env, buffer) {
  "use asm";
  var a = new global.Int8Array(buffer);
  var b = new global.Int16Array(buffer);
  var c = new global.Int32Array(buffer);
  var d = new global.Uint8Array(buffer);
  var e = new global.Uint16Array(buffer);
  var f = new global.Uint32Array(buffer);
  var g = new global.Float32Array(buffer);
  var h = new global.Float64Array(buffer);
  var i = env.STACKTOP | 0;
  var j = env.STACK_MAX | 0;
  var k = env.tempDoublePtr | 0;
  var l = env.ABORT | 0;
  var m = env.cttz_i8 | 0;
  var n = env.ctlz_i8 | 0;
  var o = env._stderr | 0;
  var p = 0;
  var q = 0;
  var r = 0;
  var s = 0;
  var t = +env.NaN,
    u = +env.Infinity;
  var v = 0,
    w = 0,
    x = 0,
    y = 0,
    z = 0.0,
    A = 0,
    B = 0,
    C = 0,
    D = 0.0;
  var E = 0;
  var F = 0;
  var G = 0;
  var H = 0;
  var I = 0;
  var J = 0;
  var K = 0;
  var L = 0;
  var M = 0;
  var N = 0;
  var O = global.Math.floor;
  var P = global.Math.abs;
  var Q = global.Math.sqrt;
  var R = global.Math.pow;
  var S = global.Math.cos;
  var T = global.Math.sin;
  var U = global.Math.tan;
  var V = global.Math.acos;
  var W = global.Math.asin;
  var X = global.Math.atan;
  var Y = global.Math.atan2;
  var Z = global.Math.exp;
  var _ = global.Math.log;
  var $ = global.Math.ceil;
  var aa = global.Math.imul;
  var ba = env.abort;
  var ca = env.assert;
  var da = env.min;
  var ea = env.invoke_iiiiii;
  var fa = env._fflush;
  var ga = env.__formatString;
  var ha = env._time;
  var ia = env._send;
  var ja = env._pwrite;
  var ka = env._emscripten_set_main_loop;
  var la = env._abort;
  var ma = env.__reallyNegative;
  var na = env._fwrite;
  var oa = env._sbrk;
  var pa = env._mkport;
  var qa = env._fprintf;
  var ra = env.___setErrNo;
  var sa = env._emscripten_memcpy_big;
  var ta = env._fileno;
  var ua = env._write;
  var va = env._emscripten_set_main_loop_timing;
  var wa = env._sysconf;
  var xa = env.___errno_location;
  var ya = 0.0;
  // EMSCRIPTEN_START_FUNCS
  function Aa(a) {
    a = a | 0;
    var b = 0;
    b = i;
    i = (i + a) | 0;
    i = (i + 15) & -16;
    return b | 0;
  }
  function Ba() {
    return i | 0;
  }
  function Ca(a) {
    a = a | 0;
    i = a;
  }
  function Da(a, b) {
    a = a | 0;
    b = b | 0;
    if (!p) {
      p = a;
      q = b;
    }
  }
  function Ea(b) {
    b = b | 0;
    a[k >> 0] = a[b >> 0];
    a[(k + 1) >> 0] = a[(b + 1) >> 0];
    a[(k + 2) >> 0] = a[(b + 2) >> 0];
    a[(k + 3) >> 0] = a[(b + 3) >> 0];
  }
  function Fa(b) {
    b = b | 0;
    a[k >> 0] = a[b >> 0];
    a[(k + 1) >> 0] = a[(b + 1) >> 0];
    a[(k + 2) >> 0] = a[(b + 2) >> 0];
    a[(k + 3) >> 0] = a[(b + 3) >> 0];
    a[(k + 4) >> 0] = a[(b + 4) >> 0];
    a[(k + 5) >> 0] = a[(b + 5) >> 0];
    a[(k + 6) >> 0] = a[(b + 6) >> 0];
    a[(k + 7) >> 0] = a[(b + 7) >> 0];
  }
  function Ga(a) {
    a = a | 0;
    E = a;
  }
  function Ha() {
    return E | 0;
  }
  function Ia(a) {
    a = a | 0;
    var b = 0,
      d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0;
    A = i;
    i = (i + 213488) | 0;
    y = (A + 80) | 0;
    z = (A + 127216) | 0;
    x = (A + 127340) | 0;
    t = (A + 127464) | 0;
    f = A;
    e = (A + 127056) | 0;
    r = (A + 127092) | 0;
    if (((a & 2) | 0) != 0 ? (c[32] | 0) == 0 : 0) {
      s = lb(65536) | 0;
      if (!s) {
        w = c[o >> 2] | 0;
        c[y >> 2] = 560;
        c[(y + 4) >> 2] = 66;
        c[(y + 8) >> 2] = 576;
        qa(w | 0, 16, y | 0) | 0;
        la();
      }
      u = (f + 0) | 0;
      v = 472 | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      u = (f + 40) | 0;
      v = 512 | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      u = (e + 0) | 0;
      w = (u + 36) | 0;
      do {
        c[u >> 2] = 0;
        u = (u + 4) | 0;
      } while ((u | 0) < (w | 0));
      bb(y, 616) | 0;
      cb(z, y, 0) | 0;
      c[(r + 120) >> 2] = c[(z + 80) >> 2];
      u = (r + 0) | 0;
      v = (z + 0) | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      u = (r + 40) | 0;
      v = (z + 40) | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      c[(r + 80) >> 2] = 1;
      u = (r + 84) | 0;
      w = (u + 36) | 0;
      do {
        c[u >> 2] = 0;
        u = (u + 4) | 0;
      } while ((u | 0) < (w | 0));
      Ta(r, r, 472);
      u = (z + 0) | 0;
      v = (f + 0) | 0;
      w = (u + 80) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      c[(z + 80) >> 2] = 1;
      u = (z + 84) | 0;
      v = (e + 0) | 0;
      w = (u + 36) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      c[(z + 120) >> 2] = 0;
      u = (x + 0) | 0;
      v = (r + 0) | 0;
      w = (u + 124) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      b = (x + 40) | 0;
      g = (x + 44) | 0;
      h = (x + 48) | 0;
      j = (x + 52) | 0;
      k = (x + 56) | 0;
      l = (x + 60) | 0;
      m = (x + 64) | 0;
      n = (x + 68) | 0;
      p = (x + 72) | 0;
      q = (x + 76) | 0;
      f = 0;
      while (1) {
        d = f << 4;
        u = (y + ((d * 124) | 0) + 0) | 0;
        v = (x + 0) | 0;
        w = (u + 124) | 0;
        do {
          c[u >> 2] = c[v >> 2];
          u = (u + 4) | 0;
          v = (v + 4) | 0;
        } while ((u | 0) < (w | 0));
        e = 1;
        do {
          w = (e + d) | 0;
          Ra(
            (y + ((w * 124) | 0)) | 0,
            (y + ((((w + -1) | 0) * 124) | 0)) | 0,
            z
          );
          e = (e + 1) | 0;
        } while ((e | 0) != 16);
        Qa(z, z);
        Qa(z, z);
        Qa(z, z);
        Qa(z, z);
        Qa(x, x);
        if ((f | 0) != 62) {
          f = (f + 1) | 0;
          if ((f | 0) == 64) break;
          else continue;
        } else {
          w = c[q >> 2] | 0;
          D = w >>> 22;
          E = (((D * 977) | 0) + (c[b >> 2] | 0)) | 0;
          D = ((D << 6) + (c[g >> 2] | 0) + (E >>> 26)) | 0;
          C = ((D >>> 26) + (c[h >> 2] | 0)) | 0;
          B = ((C >>> 26) + (c[j >> 2] | 0)) | 0;
          d = ((B >>> 26) + (c[k >> 2] | 0)) | 0;
          e = ((d >>> 26) + (c[l >> 2] | 0)) | 0;
          u = ((e >>> 26) + (c[m >> 2] | 0)) | 0;
          v = ((u >>> 26) + (c[n >> 2] | 0)) | 0;
          f = ((v >>> 26) + (c[p >> 2] | 0)) | 0;
          c[b >> 2] = 268431548 - (E & 67108863);
          c[g >> 2] = 268435196 - (D & 67108863);
          c[h >> 2] = 268435452 - (C & 67108863);
          c[j >> 2] = 268435452 - (B & 67108863);
          c[k >> 2] = 268435452 - (d & 67108863);
          c[l >> 2] = 268435452 - (e & 67108863);
          c[m >> 2] = 268435452 - (u & 67108863);
          c[n >> 2] = 268435452 - (v & 67108863);
          c[p >> 2] = 268435452 - (f & 67108863);
          c[q >> 2] = 16777212 - (w & 4194303) - (f >>> 26);
          Ra(x, x, r);
          f = 63;
          continue;
        }
      }
      jb(1024, t, y);
      b = 0;
      do {
        E = b << 4;
        kb((s + (b << 10)) | 0, (t + ((E * 84) | 0)) | 0);
        kb((s + (b << 10) + 64) | 0, (t + (((E | 1) * 84) | 0)) | 0);
        kb((s + (b << 10) + 128) | 0, (t + (((E | 2) * 84) | 0)) | 0);
        kb((s + (b << 10) + 192) | 0, (t + (((E | 3) * 84) | 0)) | 0);
        kb((s + (b << 10) + 256) | 0, (t + (((E | 4) * 84) | 0)) | 0);
        kb((s + (b << 10) + 320) | 0, (t + (((E | 5) * 84) | 0)) | 0);
        kb((s + (b << 10) + 384) | 0, (t + (((E | 6) * 84) | 0)) | 0);
        kb((s + (b << 10) + 448) | 0, (t + (((E | 7) * 84) | 0)) | 0);
        kb((s + (b << 10) + 512) | 0, (t + (((E | 8) * 84) | 0)) | 0);
        kb((s + (b << 10) + 576) | 0, (t + (((E | 9) * 84) | 0)) | 0);
        kb((s + (b << 10) + 640) | 0, (t + (((E | 10) * 84) | 0)) | 0);
        kb((s + (b << 10) + 704) | 0, (t + (((E | 11) * 84) | 0)) | 0);
        kb((s + (b << 10) + 768) | 0, (t + (((E | 12) * 84) | 0)) | 0);
        kb((s + (b << 10) + 832) | 0, (t + (((E | 13) * 84) | 0)) | 0);
        kb((s + (b << 10) + 896) | 0, (t + (((E | 14) * 84) | 0)) | 0);
        kb((s + (b << 10) + 960) | 0, (t + (((E | 15) * 84) | 0)) | 0);
        b = (b + 1) | 0;
      } while ((b | 0) != 64);
      c[32] = s;
    }
    if (!(a & 1)) {
      i = A;
      return;
    }
    if (c[2] | 0) {
      i = A;
      return;
    }
    d = lb(1048576) | 0;
    if (!d) {
      E = c[o >> 2] | 0;
      c[y >> 2] = 560;
      c[(y + 4) >> 2] = 66;
      c[(y + 8) >> 2] = 576;
      qa(E | 0, 16, y | 0) | 0;
      la();
    }
    c[(x + 120) >> 2] = 0;
    u = (x + 0) | 0;
    v = 472 | 0;
    w = (u + 40) | 0;
    do {
      c[u >> 2] = c[v >> 2];
      u = (u + 4) | 0;
      v = (v + 4) | 0;
    } while ((u | 0) < (w | 0));
    u = (x + 40) | 0;
    v = 512 | 0;
    w = (u + 40) | 0;
    do {
      c[u >> 2] = c[v >> 2];
      u = (u + 4) | 0;
      v = (v + 4) | 0;
    } while ((u | 0) < (w | 0));
    c[(x + 80) >> 2] = 1;
    u = (x + 84) | 0;
    w = (u + 36) | 0;
    do {
      c[u >> 2] = 0;
      u = (u + 4) | 0;
    } while ((u | 0) < (w | 0));
    e = lb(2031616) | 0;
    if (!e) {
      E = c[o >> 2] | 0;
      c[y >> 2] = 560;
      c[(y + 4) >> 2] = 66;
      c[(y + 8) >> 2] = 576;
      qa(E | 0, 16, y | 0) | 0;
      la();
    }
    f = lb(1376256) | 0;
    if (!f) {
      E = c[o >> 2] | 0;
      c[y >> 2] = 560;
      c[(y + 4) >> 2] = 66;
      c[(y + 8) >> 2] = 576;
      qa(E | 0, 16, y | 0) | 0;
      la();
    }
    u = (e + 0) | 0;
    v = (x + 0) | 0;
    w = (u + 124) | 0;
    do {
      c[u >> 2] = c[v >> 2];
      u = (u + 4) | 0;
      v = (v + 4) | 0;
    } while ((u | 0) < (w | 0));
    Qa(z, x);
    b = 1;
    do {
      Ra((e + ((b * 124) | 0)) | 0, z, (e + ((((b + -1) | 0) * 124) | 0)) | 0);
      b = (b + 1) | 0;
    } while ((b | 0) != 16384);
    jb(16384, f, e);
    b = 0;
    do {
      kb((d + (b << 6)) | 0, (f + ((b * 84) | 0)) | 0);
      b = (b + 1) | 0;
    } while ((b | 0) != 16384);
    mb(e);
    mb(f);
    c[2] = d;
    i = A;
    return;
  }
  function Ja(a, b, e) {
    a = a | 0;
    b = b | 0;
    e = e | 0;
    var f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0;
    f = i;
    c[a >> 2] =
      ((d[(b + 30) >> 0] | 0) << 8) |
      (d[(b + 31) >> 0] | 0) |
      ((d[(b + 29) >> 0] | 0) << 16) |
      ((d[(b + 28) >> 0] | 0) << 24);
    p = (a + 4) | 0;
    c[p >> 2] =
      ((d[(b + 26) >> 0] | 0) << 8) |
      (d[(b + 27) >> 0] | 0) |
      ((d[(b + 25) >> 0] | 0) << 16) |
      ((d[(b + 24) >> 0] | 0) << 24);
    o = (a + 8) | 0;
    c[o >> 2] =
      ((d[(b + 22) >> 0] | 0) << 8) |
      (d[(b + 23) >> 0] | 0) |
      ((d[(b + 21) >> 0] | 0) << 16) |
      ((d[(b + 20) >> 0] | 0) << 24);
    r =
      ((d[(b + 18) >> 0] | 0) << 8) |
      (d[(b + 19) >> 0] | 0) |
      ((d[(b + 17) >> 0] | 0) << 16) |
      ((d[(b + 16) >> 0] | 0) << 24);
    l = (a + 12) | 0;
    c[l >> 2] = r;
    m =
      ((d[(b + 14) >> 0] | 0) << 8) |
      (d[(b + 15) >> 0] | 0) |
      ((d[(b + 13) >> 0] | 0) << 16) |
      ((d[(b + 12) >> 0] | 0) << 24);
    k = (a + 16) | 0;
    c[k >> 2] = m;
    s =
      ((d[(b + 10) >> 0] | 0) << 8) |
      (d[(b + 11) >> 0] | 0) |
      ((d[(b + 9) >> 0] | 0) << 16) |
      ((d[(b + 8) >> 0] | 0) << 24);
    j = (a + 20) | 0;
    c[j >> 2] = s;
    n =
      ((d[(b + 6) >> 0] | 0) << 8) |
      (d[(b + 7) >> 0] | 0) |
      ((d[(b + 5) >> 0] | 0) << 16) |
      ((d[(b + 4) >> 0] | 0) << 24);
    h = (a + 24) | 0;
    c[h >> 2] = n;
    b =
      ((d[(b + 2) >> 0] | 0) << 8) |
      (d[(b + 3) >> 0] | 0) |
      ((d[(b + 1) >> 0] | 0) << 16) |
      ((d[b >> 0] | 0) << 24);
    g = (a + 28) | 0;
    c[g >> 2] = b;
    n = (m >>> 0 < 4294967294) | ((s | 0) != -1) | (((b & n) | 0) != -1);
    m = ((m | 0) == -1) & 1;
    b = ((n | (m ^ 1)) & (r >>> 0 < 3132021990)) | n;
    n = ((r >>> 0 > 3132021990) & ~b) | (m & ~n);
    m = c[o >> 2] | 0;
    b = ((m >>> 0 < 2940772411) & ~n) | b;
    n = ((m >>> 0 > 2940772411) & ~b) | n;
    r = c[p >> 2] | 0;
    b = ~(((r >>> 0 < 3218235020) & ~n) | b);
    s = c[a >> 2] | 0;
    b = ((r >>> 0 > 3218235020) & b) | n | ((s >>> 0 > 3493216576) & b);
    n = (0 - b) | 0;
    s = ob((n & 801750719) | 0, 0, s | 0, 0) | 0;
    q = E;
    c[a >> 2] = s;
    a = ob((n & 1076732275) | 0, 0, r | 0, 0) | 0;
    q = ob(a | 0, E | 0, q | 0, 0) | 0;
    a = E;
    c[p >> 2] = q;
    m = ob((n & 1354194884) | 0, 0, m | 0, 0) | 0;
    a = ob(m | 0, E | 0, a | 0, 0) | 0;
    m = E;
    c[o >> 2] = a;
    a = ob((n & 1162945305) | 0, 0, c[l >> 2] | 0, 0) | 0;
    m = ob(a | 0, E | 0, m | 0, 0) | 0;
    a = E;
    c[l >> 2] = m;
    l = ob(b | 0, 0, c[k >> 2] | 0, 0) | 0;
    a = ob(l | 0, E | 0, a | 0, 0) | 0;
    c[k >> 2] = a;
    a = ob(E | 0, 0, c[j >> 2] | 0, 0) | 0;
    c[j >> 2] = a;
    a = ob(E | 0, 0, c[h >> 2] | 0, 0) | 0;
    c[h >> 2] = a;
    a = ob(E | 0, 0, c[g >> 2] | 0, 0) | 0;
    c[g >> 2] = a;
    if (!e) {
      i = f;
      return;
    }
    c[e >> 2] = b;
    i = f;
    return;
  }
  function Ka(b, d, e, f, g) {
    b = b | 0;
    d = d | 0;
    e = e | 0;
    f = f | 0;
    g = g | 0;
    var h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0;
    v = i;
    i = (i + 464) | 0;
    t = (v + 72) | 0;
    u = v;
    c[(u + 0) >> 2] = 16843009;
    c[(u + 4) >> 2] = 16843009;
    c[(u + 8) >> 2] = 16843009;
    c[(u + 12) >> 2] = 16843009;
    c[(u + 16) >> 2] = 16843009;
    c[(u + 20) >> 2] = 16843009;
    c[(u + 24) >> 2] = 16843009;
    c[(u + 28) >> 2] = 16843009;
    r = (u + 32) | 0;
    c[(r + 0) >> 2] = 0;
    c[(r + 4) >> 2] = 0;
    c[(r + 8) >> 2] = 0;
    c[(r + 12) >> 2] = 0;
    c[(r + 16) >> 2] = 0;
    c[(r + 20) >> 2] = 0;
    c[(r + 24) >> 2] = 0;
    c[(r + 28) >> 2] = 0;
    fb(t, r);
    s = (u + 32) | 0;
    o = (t + 192) | 0;
    g = c[o >> 2] & 63;
    if (((g | 0) != 0) & (((g + 32) | 0) >>> 0 > 63)) {
      h = (64 - g) | 0;
      tb((t + g + 128) | 0, u | 0, h | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + h;
      ib(t, (t + 128) | 0);
      h = (u + h) | 0;
      g = 0;
    } else h = u;
    k = (h + 64) | 0;
    if (s >>> 0 >= k >>> 0) {
      m = (u + (-32 - h) + 64) & -64;
      l = h;
      while (1) {
        ib(t, l);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        j = (k + 64) | 0;
        if (s >>> 0 < j >>> 0) break;
        else {
          l = k;
          k = j;
        }
      }
      h = (h + m) | 0;
    }
    if (s >>> 0 > h >>> 0) {
      q = (s - h) | 0;
      tb((t + g + 128) | 0, h | 0, q | 0) | 0;
      h = ((c[o >> 2] | 0) + q) | 0;
      c[o >> 2] = h;
    } else h = c[o >> 2] | 0;
    h = h & 63;
    if (((h | 0) != 0) & (((h + 1) | 0) >>> 0 > 63)) {
      k = (64 - h) | 0;
      tb((t + h + 128) | 0, 456, k | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + k;
      ib(t, (t + 128) | 0);
      k = (456 + k) | 0;
      m = 0;
    } else {
      k = 456;
      m = h;
    }
    h = (k + 64) | 0;
    if (h >>> 0 > (457 | 0) >>> 0) h = k;
    else
      while (1) {
        ib(t, k);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        k = (h + 64) | 0;
        if (k >>> 0 > (457 | 0) >>> 0) break;
        else {
          q = h;
          h = k;
          k = q;
        }
      }
    if (h >>> 0 < (457 | 0) >>> 0) {
      q = (457 - h) | 0;
      tb((t + m + 128) | 0, h | 0, q | 0) | 0;
      h = ((c[o >> 2] | 0) + q) | 0;
      c[o >> 2] = h;
    } else h = c[o >> 2] | 0;
    q = (e + 32) | 0;
    k = h & 63;
    if (((k | 0) != 0) & (((k + 32) | 0) >>> 0 > 63)) {
      j = (64 - k) | 0;
      tb((t + k + 128) | 0, e | 0, j | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + j;
      ib(t, (t + 128) | 0);
      j = (e + j) | 0;
      k = 0;
    } else j = e;
    h = (j + 64) | 0;
    if (q >>> 0 < h >>> 0) h = j;
    else
      while (1) {
        ib(t, j);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        j = (h + 64) | 0;
        if (q >>> 0 < j >>> 0) break;
        else {
          p = h;
          h = j;
          j = p;
        }
      }
    if (q >>> 0 > h >>> 0) {
      p = (q - h) | 0;
      tb((t + k + 128) | 0, h | 0, p | 0) | 0;
      k = ((c[o >> 2] | 0) + p) | 0;
      c[o >> 2] = k;
    } else k = c[o >> 2] | 0;
    p = (d + 32) | 0;
    k = k & 63;
    if (((k | 0) != 0) & (((k + 32) | 0) >>> 0 > 63)) {
      l = (64 - k) | 0;
      tb((t + k + 128) | 0, d | 0, l | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + l;
      ib(t, (t + 128) | 0);
      l = (d + l) | 0;
      m = 0;
    } else {
      l = d;
      m = k;
    }
    k = (l + 64) | 0;
    if (p >>> 0 < k >>> 0) k = l;
    else
      while (1) {
        ib(t, l);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        l = (k + 64) | 0;
        if (p >>> 0 < l >>> 0) break;
        else {
          n = k;
          k = l;
          l = n;
        }
      }
    if (p >>> 0 > k >>> 0) {
      n = (p - k) | 0;
      tb((t + m + 128) | 0, k | 0, n | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + n;
    }
    gb(t, r);
    fb(t, r);
    j = c[o >> 2] & 63;
    if (((j | 0) != 0) & (((j + 32) | 0) >>> 0 > 63)) {
      k = (64 - j) | 0;
      tb((t + j + 128) | 0, u | 0, k | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + k;
      ib(t, (t + 128) | 0);
      k = (u + k) | 0;
      j = 0;
    } else k = u;
    l = (k + 64) | 0;
    if (s >>> 0 >= l >>> 0) {
      g = (u + (-32 - k) + 64) & -64;
      m = k;
      while (1) {
        ib(t, m);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        h = (l + 64) | 0;
        if (s >>> 0 < h >>> 0) break;
        else {
          m = l;
          l = h;
        }
      }
      k = (k + g) | 0;
    }
    if (s >>> 0 > k >>> 0) {
      n = (s - k) | 0;
      tb((t + j + 128) | 0, k | 0, n | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + n;
    }
    gb(t, u);
    fb(t, r);
    j = c[o >> 2] & 63;
    if (((j | 0) != 0) & (((j + 32) | 0) >>> 0 > 63)) {
      k = (64 - j) | 0;
      tb((t + j + 128) | 0, u | 0, k | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + k;
      ib(t, (t + 128) | 0);
      k = (u + k) | 0;
      j = 0;
    } else k = u;
    l = (k + 64) | 0;
    if (s >>> 0 >= l >>> 0) {
      g = (u + (-32 - k) + 64) & -64;
      m = k;
      while (1) {
        ib(t, m);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        h = (l + 64) | 0;
        if (s >>> 0 < h >>> 0) break;
        else {
          m = l;
          l = h;
        }
      }
      k = (k + g) | 0;
    }
    if (s >>> 0 > k >>> 0) {
      h = (s - k) | 0;
      tb((t + j + 128) | 0, k | 0, h | 0) | 0;
      h = ((c[o >> 2] | 0) + h) | 0;
      c[o >> 2] = h;
    } else h = c[o >> 2] | 0;
    k = h & 63;
    if (((k | 0) != 0) & (((k + 1) | 0) >>> 0 > 63)) {
      l = (64 - k) | 0;
      tb((t + k + 128) | 0, 464, l | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + l;
      ib(t, (t + 128) | 0);
      l = (464 + l) | 0;
      m = 0;
    } else {
      l = 464;
      m = k;
    }
    k = (l + 64) | 0;
    if (k >>> 0 > (465 | 0) >>> 0) k = l;
    else
      while (1) {
        ib(t, l);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        j = (k + 64) | 0;
        if (j >>> 0 > (465 | 0) >>> 0) break;
        else {
          l = k;
          k = j;
        }
      }
    if (k >>> 0 < (465 | 0) >>> 0) {
      h = (465 - k) | 0;
      tb((t + m + 128) | 0, k | 0, h | 0) | 0;
      h = ((c[o >> 2] | 0) + h) | 0;
      c[o >> 2] = h;
    } else h = c[o >> 2] | 0;
    k = h & 63;
    if (((k | 0) != 0) & (((k + 32) | 0) >>> 0 > 63)) {
      j = (64 - k) | 0;
      tb((t + k + 128) | 0, e | 0, j | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + j;
      ib(t, (t + 128) | 0);
      j = (e + j) | 0;
      k = 0;
    } else j = e;
    h = (j + 64) | 0;
    if (q >>> 0 < h >>> 0) h = j;
    else
      while (1) {
        ib(t, j);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        j = (h + 64) | 0;
        if (q >>> 0 < j >>> 0) break;
        else {
          e = h;
          h = j;
          j = e;
        }
      }
    if (q >>> 0 > h >>> 0) {
      q = (q - h) | 0;
      tb((t + k + 128) | 0, h | 0, q | 0) | 0;
      h = ((c[o >> 2] | 0) + q) | 0;
      c[o >> 2] = h;
    } else h = c[o >> 2] | 0;
    h = h & 63;
    if (((h | 0) != 0) & (((h + 32) | 0) >>> 0 > 63)) {
      g = (64 - h) | 0;
      tb((t + h + 128) | 0, d | 0, g | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + g;
      ib(t, (t + 128) | 0);
      g = (d + g) | 0;
      l = 0;
    } else {
      g = d;
      l = h;
    }
    h = (g + 64) | 0;
    if (p >>> 0 < h >>> 0) h = g;
    else
      while (1) {
        ib(t, g);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        g = (h + 64) | 0;
        if (p >>> 0 < g >>> 0) break;
        else {
          q = h;
          h = g;
          g = q;
        }
      }
    if (p >>> 0 > h >>> 0) {
      q = (p - h) | 0;
      tb((t + l + 128) | 0, h | 0, q | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + q;
    }
    gb(t, r);
    fb(t, r);
    h = c[o >> 2] & 63;
    if (((h | 0) != 0) & (((h + 32) | 0) >>> 0 > 63)) {
      g = (64 - h) | 0;
      tb((t + h + 128) | 0, u | 0, g | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + g;
      ib(t, (t + 128) | 0);
      g = (u + g) | 0;
      h = 0;
    } else g = u;
    j = (g + 64) | 0;
    if (s >>> 0 >= j >>> 0) {
      l = (u + (-32 - g) + 64) & -64;
      k = g;
      while (1) {
        ib(t, k);
        c[o >> 2] = (c[o >> 2] | 0) + 64;
        k = (j + 64) | 0;
        if (s >>> 0 < k >>> 0) break;
        else {
          q = j;
          j = k;
          k = q;
        }
      }
      g = (g + l) | 0;
    }
    if (s >>> 0 > g >>> 0) {
      q = s;
      p = (q - g) | 0;
      tb((t + h + 128) | 0, g | 0, p | 0) | 0;
      c[o >> 2] = (c[o >> 2] | 0) + p;
      g = q;
    } else g = s;
    gb(t, u);
    n = (u + 64) | 0;
    c[n >> 2] = 0;
    o = (t + 192) | 0;
    d = (t + 128) | 0;
    e = (t + 192) | 0;
    p = (t + 128) | 0;
    l = 1;
    q = 0;
    while (1) {
      if (!l) {
        fb(t, r);
        k = c[e >> 2] & 63;
        if (((k | 0) != 0) & (((k + 32) | 0) >>> 0 > 63)) {
          l = (64 - k) | 0;
          tb((t + k + 128) | 0, u | 0, l | 0) | 0;
          c[e >> 2] = (c[e >> 2] | 0) + l;
          ib(t, p);
          l = (u + l) | 0;
          k = 0;
        } else l = u;
        m = (l + 64) | 0;
        if (s >>> 0 >= m >>> 0) {
          h = (u + (-32 - l)) | 0;
          j = l;
          while (1) {
            ib(t, j);
            c[e >> 2] = (c[e >> 2] | 0) + 64;
            j = (m + 64) | 0;
            if (s >>> 0 < j >>> 0) break;
            else {
              w = m;
              m = j;
              j = w;
            }
          }
          l = (l + ((h + 64) & -64)) | 0;
        }
        if (s >>> 0 > l >>> 0) {
          w = (g - l) | 0;
          tb((t + k + 128) | 0, l | 0, w | 0) | 0;
          l = ((c[e >> 2] | 0) + w) | 0;
          c[e >> 2] = l;
        } else l = c[e >> 2] | 0;
        l = l & 63;
        if (((l | 0) != 0) & (((l + 1) | 0) >>> 0 > 63)) {
          m = (64 - l) | 0;
          tb((t + l + 128) | 0, 384, m | 0) | 0;
          c[e >> 2] = (c[e >> 2] | 0) + m;
          ib(t, p);
          m = (384 + m) | 0;
          k = 0;
        } else {
          m = 384;
          k = l;
        }
        l = (m + 64) | 0;
        if (l >>> 0 > (385 | 0) >>> 0) l = m;
        else
          while (1) {
            ib(t, m);
            c[e >> 2] = (c[e >> 2] | 0) + 64;
            m = (l + 64) | 0;
            if (m >>> 0 > (385 | 0) >>> 0) break;
            else {
              w = l;
              l = m;
              m = w;
            }
          }
        if (l >>> 0 < (385 | 0) >>> 0) {
          w = (385 - l) | 0;
          tb((t + k + 128) | 0, l | 0, w | 0) | 0;
          c[e >> 2] = (c[e >> 2] | 0) + w;
        }
        gb(t, r);
        fb(t, r);
        k = c[e >> 2] & 63;
        if (((k | 0) != 0) & (((k + 32) | 0) >>> 0 > 63)) {
          l = (64 - k) | 0;
          tb((t + k + 128) | 0, u | 0, l | 0) | 0;
          c[e >> 2] = (c[e >> 2] | 0) + l;
          ib(t, p);
          l = (u + l) | 0;
          k = 0;
        } else l = u;
        m = (l + 64) | 0;
        if (s >>> 0 >= m >>> 0) {
          h = (u + (-32 - l)) | 0;
          j = l;
          while (1) {
            ib(t, j);
            c[e >> 2] = (c[e >> 2] | 0) + 64;
            j = (m + 64) | 0;
            if (s >>> 0 < j >>> 0) break;
            else {
              w = m;
              m = j;
              j = w;
            }
          }
          l = (l + ((h + 64) & -64)) | 0;
        }
        if (s >>> 0 > l >>> 0) {
          w = (g - l) | 0;
          tb((t + k + 128) | 0, l | 0, w | 0) | 0;
          c[e >> 2] = (c[e >> 2] | 0) + w;
        }
        gb(t, u);
      }
      fb(t, r);
      k = c[o >> 2] & 63;
      if (((k | 0) != 0) & (((k + 32) | 0) >>> 0 > 63)) {
        l = (64 - k) | 0;
        tb((t + k + 128) | 0, u | 0, l | 0) | 0;
        c[o >> 2] = (c[o >> 2] | 0) + l;
        ib(t, d);
        l = (u + l) | 0;
        k = 0;
      } else l = u;
      m = (l + 64) | 0;
      if (s >>> 0 >= m >>> 0) {
        h = (u + (-32 - l)) | 0;
        j = l;
        while (1) {
          ib(t, j);
          c[o >> 2] = (c[o >> 2] | 0) + 64;
          j = (m + 64) | 0;
          if (s >>> 0 < j >>> 0) break;
          else {
            w = m;
            m = j;
            j = w;
          }
        }
        l = (l + ((h + 64) & -64)) | 0;
      }
      if (s >>> 0 > l >>> 0) {
        w = (g - l) | 0;
        tb((t + k + 128) | 0, l | 0, w | 0) | 0;
        c[o >> 2] = (c[o >> 2] | 0) + w;
      }
      gb(t, u);
      m = (b + 0) | 0;
      l = (u + 0) | 0;
      k = (m + 32) | 0;
      do {
        a[m >> 0] = a[l >> 0] | 0;
        m = (m + 1) | 0;
        l = (l + 1) | 0;
      } while ((m | 0) < (k | 0));
      c[n >> 2] = 1;
      q = (q + 1) | 0;
      if (q >>> 0 > f >>> 0) break;
      else l = 0;
    }
    i = v;
    return 1;
  }
  function La(b, d, e, f, g, h) {
    b = b | 0;
    d = d | 0;
    e = e | 0;
    f = f | 0;
    g = g | 0;
    h = h | 0;
    var j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0;
    D = i;
    i = (i + 288) | 0;
    n = D;
    p = (D + 240) | 0;
    B = (D + 72) | 0;
    A = (D + 40) | 0;
    x = (D + 176) | 0;
    w = (D + 144) | 0;
    z = (D + 136) | 0;
    y = (D + 208) | 0;
    c[z >> 2] = 0;
    if (!(c[32] | 0)) {
      v = c[o >> 2] | 0;
      c[n >> 2] = 32;
      c[(n + 4) >> 2] = 86;
      c[(n + 8) >> 2] = 136;
      qa(v | 0, 16, n | 0) | 0;
      la();
    }
    if (!b) {
      v = c[o >> 2] | 0;
      c[n >> 2] = 32;
      c[(n + 4) >> 2] = 87;
      c[(n + 8) >> 2] = 48;
      qa(v | 0, 16, n | 0) | 0;
      la();
    }
    if (!d) {
      v = c[o >> 2] | 0;
      c[n >> 2] = 32;
      c[(n + 4) >> 2] = 88;
      c[(n + 8) >> 2] = 200;
      qa(v | 0, 16, n | 0) | 0;
      la();
    }
    if (!e) {
      v = c[o >> 2] | 0;
      c[n >> 2] = 32;
      c[(n + 4) >> 2] = 89;
      c[(n + 8) >> 2] = 248;
      qa(v | 0, 16, n | 0) | 0;
      la();
    }
    if (!f) {
      v = c[o >> 2] | 0;
      c[n >> 2] = 32;
      c[(n + 4) >> 2] = 90;
      c[(n + 8) >> 2] = 296;
      qa(v | 0, 16, n | 0) | 0;
      la();
    }
    t = (g | 0) == 0 ? 1 : g;
    Ja(A, f, 0);
    Ja(w, b, 0);
    if (!(za[t & 1](y, b, f, 0, h) | 0)) {
      e = 0;
      i = D;
      return e | 0;
    }
    g = (x + 4) | 0;
    m = (x + 8) | 0;
    l = (x + 12) | 0;
    k = (x + 16) | 0;
    j = (x + 20) | 0;
    q = (x + 24) | 0;
    r = (x + 28) | 0;
    s = 0;
    while (1) {
      Ja(x, y, z);
      u = (y + 0) | 0;
      v = (u + 32) | 0;
      do {
        a[u >> 0] = 0;
        u = (u + 1) | 0;
      } while ((u | 0) < (v | 0));
      if (
        (((c[g >> 2] |
          c[x >> 2] |
          c[m >> 2] |
          c[l >> 2] |
          c[k >> 2] |
          c[j >> 2] |
          c[q >> 2] |
          c[r >> 2] |
          0) ==
          0) |
          c[z >> 2] |
          0) ==
        0
          ? (Ma(B, A, w, x, 0) | 0) != 0
          : 0
      )
        break;
      s = (s + 1) | 0;
      if (!(za[t & 1](y, b, f, s, h) | 0)) {
        j = 0;
        C = 26;
        break;
      }
    }
    if ((C | 0) == 26) {
      i = D;
      return j | 0;
    }
    u = (n + 0) | 0;
    v = (u + 33) | 0;
    do {
      a[u >> 0] = 0;
      u = (u + 1) | 0;
    } while ((u | 0) < (v | 0));
    u = (p + 0) | 0;
    v = (u + 33) | 0;
    do {
      a[u >> 0] = 0;
      u = (u + 1) | 0;
    } while ((u | 0) < (v | 0));
    Na((n + 1) | 0, B);
    Na((p + 1) | 0, (B + 32) | 0);
    m = a[n >> 0] | 0;
    k = 33;
    while (1) {
      if ((m << 24) >> 24) {
        j = k;
        break;
      }
      l = (n + 1) | 0;
      m = a[l >> 0] | 0;
      j = (k + -1) | 0;
      if ((m << 24) >> 24 <= -1) {
        j = k;
        break;
      }
      if ((j | 0) <= 1) {
        n = l;
        break;
      } else {
        k = j;
        n = l;
      }
    }
    k = a[p >> 0] | 0;
    g = 33;
    while (1) {
      if ((k << 24) >> 24) {
        m = p;
        break;
      }
      m = (p + 1) | 0;
      k = a[m >> 0] | 0;
      l = (g + -1) | 0;
      if ((k << 24) >> 24 <= -1) {
        m = p;
        break;
      }
      if ((l | 0) <= 1) {
        g = l;
        break;
      } else {
        g = l;
        p = m;
      }
    }
    k = (j + 6) | 0;
    l = (g + k) | 0;
    if ((c[e >> 2] | 0) < (l | 0)) {
      e = 0;
      i = D;
      return e | 0;
    }
    c[e >> 2] = l;
    a[d >> 0] = 48;
    e = (j + 4) | 0;
    a[(d + 1) >> 0] = g + e;
    a[(d + 2) >> 0] = 2;
    a[(d + 3) >> 0] = j;
    tb((d + 4) | 0, n | 0, j | 0) | 0;
    a[(d + e) >> 0] = 2;
    a[(d + (j + 5)) >> 0] = g;
    tb((d + k) | 0, m | 0, g | 0) | 0;
    e = 1;
    i = D;
    return e | 0;
  }
  function Ma(b, d, e, f, g) {
    b = b | 0;
    d = d | 0;
    e = e | 0;
    f = f | 0;
    g = g | 0;
    var h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0;
    w = i;
    i = (i + 368) | 0;
    h = (w + 88) | 0;
    o = (w + 136) | 0;
    k = (w + 336) | 0;
    r = (w + 208) | 0;
    q = w;
    p = (w + 176) | 0;
    m = (w + 128) | 0;
    c[m >> 2] = 0;
    Pa(r, f);
    c[(q + 80) >> 2] = c[(r + 120) >> 2];
    n = (r + 80) | 0;
    _a(n, n);
    Ua(h, n);
    Va(o, n, h);
    Va(r, r, h);
    h = (r + 40) | 0;
    Va(h, h, o);
    c[n >> 2] = 1;
    n = (r + 84) | 0;
    o = (n + 36) | 0;
    do {
      c[n >> 2] = 0;
      n = (n + 4) | 0;
    } while ((n | 0) < (o | 0));
    n = (q + 0) | 0;
    j = (r + 0) | 0;
    o = (n + 40) | 0;
    do {
      c[n >> 2] = c[j >> 2];
      n = (n + 4) | 0;
      j = (j + 4) | 0;
    } while ((n | 0) < (o | 0));
    l = (q + 40) | 0;
    n = (l + 0) | 0;
    j = (h + 0) | 0;
    o = (n + 40) | 0;
    do {
      c[n >> 2] = c[j >> 2];
      n = (n + 4) | 0;
      j = (j + 4) | 0;
    } while ((n | 0) < (o | 0));
    $a(q);
    $a(l);
    h = 0;
    do {
      t = h << 3;
      s = t | 2;
      u = t | 4;
      v = t | 6;
      a[(k + (31 - h)) >> 0] =
        ((((c[(q + ((((s | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((s | 0) % 26 | 0)) <<
          2) &
          12) |
        (((c[(q + ((((t | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((t | 0) % 26 | 0)) &
          3) |
        ((((c[(q + ((((u | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((u | 0) % 26 | 0)) <<
          4) &
          48) |
        (((c[(q + ((((v | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((v | 0) % 26 | 0)) <<
          6);
      h = (h + 1) | 0;
    } while ((h | 0) != 32);
    Ja(b, k, m);
    if (
      !(
        c[(b + 4) >> 2] |
        c[b >> 2] |
        c[(b + 8) >> 2] |
        c[(b + 12) >> 2] |
        c[(b + 16) >> 2] |
        c[(b + 20) >> 2] |
        c[(b + 24) >> 2] |
        c[(b + 28) >> 2]
      )
    ) {
      n = (r + 0) | 0;
      o = (n + 124) | 0;
      do {
        c[n >> 2] = 0;
        n = (n + 4) | 0;
      } while ((n | 0) < (o | 0));
      n = (q + 0) | 0;
      o = (n + 84) | 0;
      do {
        c[n >> 2] = 0;
        n = (n + 4) | 0;
      } while ((n | 0) < (o | 0));
      g = 0;
      i = w;
      return g | 0;
    }
    v = (g | 0) != 0;
    if (v) c[g >> 2] = ((c[m >> 2] | 0) != 0 ? 2 : 0) | (c[l >> 2] & 1);
    Xa(p, b, d);
    Za(p, p, e);
    u = (b + 32) | 0;
    db(u, f);
    Xa(u, u, p);
    c[(p + 0) >> 2] = 0;
    c[(p + 4) >> 2] = 0;
    c[(p + 8) >> 2] = 0;
    c[(p + 12) >> 2] = 0;
    c[(p + 16) >> 2] = 0;
    c[(p + 20) >> 2] = 0;
    c[(p + 24) >> 2] = 0;
    c[(p + 28) >> 2] = 0;
    n = (r + 0) | 0;
    o = (n + 124) | 0;
    do {
      c[n >> 2] = 0;
      n = (n + 4) | 0;
    } while ((n | 0) < (o | 0));
    n = (q + 0) | 0;
    o = (n + 84) | 0;
    do {
      c[n >> 2] = 0;
      n = (n + 4) | 0;
    } while ((n | 0) < (o | 0));
    r = c[u >> 2] | 0;
    q = (b + 36) | 0;
    f = c[q >> 2] | 0;
    p = (b + 40) | 0;
    d = c[p >> 2] | 0;
    m = (b + 44) | 0;
    e = c[m >> 2] | 0;
    l = (b + 48) | 0;
    k = c[l >> 2] | 0;
    j = (b + 52) | 0;
    h = c[j >> 2] | 0;
    s = (b + 56) | 0;
    t = c[s >> 2] | 0;
    o = (b + 60) | 0;
    n = c[o >> 2] | 0;
    if (!(f | r | d | e | k | h | t | n)) {
      g = 0;
      i = w;
      return g | 0;
    }
    x = (n >>> 0 < 2147483647) & 1;
    y = n >>> 31;
    b = x | ~y;
    b =
      (b & ((t | 0) != -1)) |
      x |
      (b & ((h | 0) != -1)) |
      (b & ((k | 0) != -1)) |
      (b & (e >>> 0 < 1566010995));
    x = ((e >>> 0 > 1566010995) & ~b) | (y & ~x);
    b = ((d >>> 0 < 1470386205) & ~x) | b;
    x = ((d >>> 0 > 1470386205) & ~b) | x;
    b = ~(((f >>> 0 < 3756601158) & ~x) | b);
    if (!(((f >>> 0 > 3756601158) & b) | x | ((r >>> 0 > 1746608288) & b))) {
      y = 1;
      i = w;
      return y | 0;
    }
    y = ob(~r | 0, 0, -801750718, 0) | 0;
    c[u >> 2] = y;
    y = ob(E | 0, 0, -1076732276, 0) | 0;
    y = ob(y | 0, E | 0, ~f | 0, 0) | 0;
    x = E;
    c[q >> 2] = y;
    y = ob(~d | 0, 0, -1354194885, 0) | 0;
    x = ob(y | 0, E | 0, x | 0, 0) | 0;
    y = E;
    c[p >> 2] = x;
    x = ob(~e | 0, 0, -1162945306, 0) | 0;
    y = ob(x | 0, E | 0, y | 0, 0) | 0;
    x = E;
    c[m >> 2] = y;
    y = ob(~k | 0, 0, -2, 0) | 0;
    x = ob(y | 0, E | 0, x | 0, 0) | 0;
    y = E;
    c[l >> 2] = x;
    x = ob(~h | 0, 0, -1, 0) | 0;
    y = ob(x | 0, E | 0, y | 0, 0) | 0;
    x = E;
    c[j >> 2] = y;
    y = ob(~t | 0, 0, -1, 0) | 0;
    x = ob(y | 0, E | 0, x | 0, 0) | 0;
    y = E;
    c[s >> 2] = x;
    x = ob(~n | 0, 0, -1, 0) | 0;
    y = ob(x | 0, E | 0, y | 0, 0) | 0;
    c[o >> 2] = y;
    if (!v) {
      y = 1;
      i = w;
      return y | 0;
    }
    c[g >> 2] = c[g >> 2] ^ 1;
    y = 1;
    i = w;
    return y | 0;
  }
  function Na(b, d) {
    b = b | 0;
    d = d | 0;
    var e = 0;
    e = (d + 28) | 0;
    a[b >> 0] = (c[e >> 2] | 0) >>> 24;
    a[(b + 1) >> 0] = (c[e >> 2] | 0) >>> 16;
    a[(b + 2) >> 0] = (c[e >> 2] | 0) >>> 8;
    a[(b + 3) >> 0] = c[e >> 2];
    e = (d + 24) | 0;
    a[(b + 4) >> 0] = (c[e >> 2] | 0) >>> 24;
    a[(b + 5) >> 0] = (c[e >> 2] | 0) >>> 16;
    a[(b + 6) >> 0] = (c[e >> 2] | 0) >>> 8;
    a[(b + 7) >> 0] = c[e >> 2];
    e = (d + 20) | 0;
    a[(b + 8) >> 0] = (c[e >> 2] | 0) >>> 24;
    a[(b + 9) >> 0] = (c[e >> 2] | 0) >>> 16;
    a[(b + 10) >> 0] = (c[e >> 2] | 0) >>> 8;
    a[(b + 11) >> 0] = c[e >> 2];
    e = (d + 16) | 0;
    a[(b + 12) >> 0] = (c[e >> 2] | 0) >>> 24;
    a[(b + 13) >> 0] = (c[e >> 2] | 0) >>> 16;
    a[(b + 14) >> 0] = (c[e >> 2] | 0) >>> 8;
    a[(b + 15) >> 0] = c[e >> 2];
    e = (d + 12) | 0;
    a[(b + 16) >> 0] = (c[e >> 2] | 0) >>> 24;
    a[(b + 17) >> 0] = (c[e >> 2] | 0) >>> 16;
    a[(b + 18) >> 0] = (c[e >> 2] | 0) >>> 8;
    a[(b + 19) >> 0] = c[e >> 2];
    e = (d + 8) | 0;
    a[(b + 20) >> 0] = (c[e >> 2] | 0) >>> 24;
    a[(b + 21) >> 0] = (c[e >> 2] | 0) >>> 16;
    a[(b + 22) >> 0] = (c[e >> 2] | 0) >>> 8;
    a[(b + 23) >> 0] = c[e >> 2];
    e = (d + 4) | 0;
    a[(b + 24) >> 0] = (c[e >> 2] | 0) >>> 24;
    a[(b + 25) >> 0] = (c[e >> 2] | 0) >>> 16;
    a[(b + 26) >> 0] = (c[e >> 2] | 0) >>> 8;
    a[(b + 27) >> 0] = c[e >> 2];
    a[(b + 28) >> 0] = (c[d >> 2] | 0) >>> 24;
    a[(b + 29) >> 0] = (c[d >> 2] | 0) >>> 16;
    a[(b + 30) >> 0] = (c[d >> 2] | 0) >>> 8;
    a[(b + 31) >> 0] = c[d >> 2];
    return;
  }
  function Oa(b, d, e, f) {
    b = b | 0;
    d = d | 0;
    e = e | 0;
    f = f | 0;
    var g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      p = 0;
    p = i;
    i = (i + 320) | 0;
    h = p;
    j = (p + 280) | 0;
    m = (p + 156) | 0;
    n = (p + 72) | 0;
    g = (p + 40) | 0;
    if (!(c[32] | 0)) {
      l = c[o >> 2] | 0;
      c[h >> 2] = 32;
      c[(h + 4) >> 2] = 214;
      c[(h + 8) >> 2] = 136;
      qa(l | 0, 16, h | 0) | 0;
      la();
    }
    if (!b) {
      l = c[o >> 2] | 0;
      c[h >> 2] = 32;
      c[(h + 4) >> 2] = 215;
      c[(h + 8) >> 2] = 88;
      qa(l | 0, 16, h | 0) | 0;
      la();
    }
    if (!d) {
      l = c[o >> 2] | 0;
      c[h >> 2] = 32;
      c[(h + 4) >> 2] = 216;
      c[(h + 8) >> 2] = 336;
      qa(l | 0, 16, h | 0) | 0;
      la();
    }
    if (!e) {
      l = c[o >> 2] | 0;
      c[h >> 2] = 32;
      c[(h + 4) >> 2] = 217;
      c[(h + 8) >> 2] = 296;
      qa(l | 0, 16, h | 0) | 0;
      la();
    }
    Ja(g, e, 0);
    Pa(m, g);
    c[(g + 0) >> 2] = 0;
    c[(g + 4) >> 2] = 0;
    c[(g + 8) >> 2] = 0;
    c[(g + 12) >> 2] = 0;
    c[(g + 16) >> 2] = 0;
    c[(g + 20) >> 2] = 0;
    c[(g + 24) >> 2] = 0;
    c[(g + 28) >> 2] = 0;
    l = c[(m + 120) >> 2] | 0;
    c[(n + 80) >> 2] = l;
    g = (m + 80) | 0;
    _a(g, g);
    Ua(h, g);
    Va(j, g, h);
    Va(m, m, h);
    k = (m + 40) | 0;
    Va(k, k, j);
    c[g >> 2] = 1;
    j = (m + 84) | 0;
    g = (j + 36) | 0;
    do {
      c[j >> 2] = 0;
      j = (j + 4) | 0;
    } while ((j | 0) < (g | 0));
    j = (n + 0) | 0;
    h = (m + 0) | 0;
    g = (j + 40) | 0;
    do {
      c[j >> 2] = c[h >> 2];
      j = (j + 4) | 0;
      h = (h + 4) | 0;
    } while ((j | 0) < (g | 0));
    e = (n + 40) | 0;
    j = (e + 0) | 0;
    h = (k + 0) | 0;
    g = (j + 40) | 0;
    do {
      c[j >> 2] = c[h >> 2];
      j = (j + 4) | 0;
      h = (h + 4) | 0;
    } while ((j | 0) < (g | 0));
    if (l) {
      b = 0;
      i = p;
      return b | 0;
    }
    ab(n);
    ab(e);
    g = 0;
    do {
      k = g << 3;
      j = k | 2;
      l = k | 4;
      m = k | 6;
      a[(b + (32 - g)) >> 0] =
        ((((c[(n + ((((j | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((j | 0) % 26 | 0)) <<
          2) &
          12) |
        (((c[(n + ((((k | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((k | 0) % 26 | 0)) &
          3) |
        ((((c[(n + ((((l | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((l | 0) % 26 | 0)) <<
          4) &
          48) |
        (((c[(n + ((((m | 0) / 26) | 0) << 2)) >> 2] | 0) >>>
          ((m | 0) % 26 | 0)) <<
          6);
      g = (g + 1) | 0;
    } while ((g | 0) != 32);
    if (f) {
      c[d >> 2] = 33;
      a[b >> 0] = (c[e >> 2] & 1) | 2;
      b = 1;
      i = p;
      return b | 0;
    }
    c[d >> 2] = 65;
    a[b >> 0] = 4;
    g = 0;
    do {
      m = g << 3;
      l = m | 2;
      f = m | 4;
      d = m | 6;
      a[(b + (64 - g)) >> 0] =
        ((((c[(n + ((((l | 0) / 26) | 0) << 2) + 40) >> 2] | 0) >>>
          ((l | 0) % 26 | 0)) <<
          2) &
          12) |
        (((c[(n + ((((m | 0) / 26) | 0) << 2) + 40) >> 2] | 0) >>>
          ((m | 0) % 26 | 0)) &
          3) |
        ((((c[(n + ((((f | 0) / 26) | 0) << 2) + 40) >> 2] | 0) >>>
          ((f | 0) % 26 | 0)) <<
          4) &
          48) |
        (((c[(n + ((((d | 0) / 26) | 0) << 2) + 40) >> 2] | 0) >>>
          ((d | 0) % 26 | 0)) <<
          6);
      g = (g + 1) | 0;
    } while ((g | 0) != 32);
    g = 1;
    i = p;
    return g | 0;
  }
  function Pa(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0,
      N = 0,
      O = 0,
      P = 0,
      Q = 0,
      R = 0,
      S = 0,
      T = 0,
      U = 0,
      V = 0,
      W = 0,
      X = 0,
      Y = 0,
      Z = 0,
      _ = 0,
      $ = 0,
      ba = 0,
      ca = 0,
      da = 0,
      ea = 0,
      fa = 0,
      ga = 0,
      ha = 0,
      ia = 0,
      ja = 0,
      ka = 0,
      la = 0,
      ma = 0,
      na = 0,
      oa = 0,
      pa = 0,
      qa = 0,
      ra = 0,
      sa = 0,
      ta = 0,
      ua = 0,
      va = 0,
      wa = 0,
      xa = 0,
      ya = 0,
      za = 0,
      Aa = 0,
      Ba = 0,
      Ca = 0,
      Da = 0,
      Ea = 0,
      Fa = 0,
      Ga = 0,
      Ha = 0,
      Ia = 0,
      Ja = 0,
      Ka = 0,
      La = 0,
      Ma = 0,
      Na = 0,
      Oa = 0,
      Pa = 0,
      Qa = 0,
      Ra = 0,
      Ta = 0,
      Wa = 0,
      Xa = 0,
      Ya = 0,
      Za = 0,
      _a = 0,
      ab = 0,
      bb = 0,
      cb = 0,
      db = 0,
      eb = 0,
      fb = 0,
      gb = 0,
      hb = 0,
      ib = 0,
      jb = 0,
      kb = 0,
      lb = 0,
      mb = 0,
      nb = 0,
      ob = 0,
      pb = 0,
      qb = 0,
      rb = 0,
      sb = 0,
      tb = 0,
      ub = 0,
      vb = 0,
      wb = 0,
      xb = 0,
      yb = 0,
      zb = 0,
      Ab = 0,
      Bb = 0,
      Cb = 0,
      Db = 0,
      Eb = 0,
      Fb = 0,
      Gb = 0,
      Hb = 0,
      Ib = 0,
      Jb = 0,
      Kb = 0,
      Lb = 0,
      Mb = 0,
      Nb = 0,
      Ob = 0,
      Pb = 0,
      Qb = 0,
      Rb = 0,
      Sb = 0,
      Tb = 0,
      Ub = 0,
      Vb = 0,
      Wb = 0,
      Xb = 0,
      Yb = 0,
      Zb = 0,
      _b = 0,
      $b = 0,
      ac = 0,
      bc = 0,
      cc = 0,
      dc = 0,
      ec = 0,
      fc = 0,
      gc = 0,
      hc = 0,
      ic = 0,
      jc = 0,
      kc = 0,
      lc = 0;
    ec = i;
    i = (i + 560) | 0;
    dc = (ec + 40) | 0;
    ac = (ec + 208) | 0;
    bc = (ec + 432) | 0;
    _b = ec;
    cc = (ec + 392) | 0;
    $b = (ec + 472) | 0;
    Wb = (ec + 512) | 0;
    Xb = (ec + 288) | 0;
    Yb = (ec + 248) | 0;
    Zb = (ec + 80) | 0;
    Tb = (ec + 120) | 0;
    Ub = (ec + 328) | 0;
    D = c[32] | 0;
    E = (a + 120) | 0;
    c[E >> 2] = 1;
    A = (a + 0) | 0;
    C = (A + 120) | 0;
    do {
      c[A >> 2] = 0;
      A = (A + 4) | 0;
    } while ((A | 0) < (C | 0));
    c[(Tb + 80) >> 2] = 0;
    sa = (Ub + 4) | 0;
    Da = (Ub + 8) | 0;
    Oa = (Ub + 12) | 0;
    bb = (Ub + 16) | 0;
    mb = (Ub + 20) | 0;
    xb = (Ub + 24) | 0;
    Ib = (Ub + 28) | 0;
    F = (Ub + 32) | 0;
    Q = (Ub + 36) | 0;
    $ = (Ub + 40) | 0;
    ba = (Ub + 44) | 0;
    ca = (Ub + 48) | 0;
    da = (Ub + 52) | 0;
    ea = (Ub + 56) | 0;
    fa = (Ub + 60) | 0;
    ga = (a + 80) | 0;
    ha = (ac + 4) | 0;
    ia = (ac + 8) | 0;
    ja = (ac + 12) | 0;
    ka = (ac + 16) | 0;
    la = (ac + 20) | 0;
    ma = (ac + 24) | 0;
    na = (ac + 28) | 0;
    oa = (ac + 32) | 0;
    pa = (ac + 36) | 0;
    qa = (a + 40) | 0;
    ra = (a + 44) | 0;
    ta = (a + 48) | 0;
    ua = (a + 52) | 0;
    va = (a + 56) | 0;
    wa = (a + 60) | 0;
    xa = (a + 64) | 0;
    ya = (a + 68) | 0;
    za = (a + 72) | 0;
    Aa = (a + 76) | 0;
    Ba = (Tb + 40) | 0;
    Ca = (bc + 4) | 0;
    Ea = ($b + 4) | 0;
    Fa = (bc + 8) | 0;
    Ga = ($b + 8) | 0;
    Ha = (bc + 12) | 0;
    Ia = ($b + 12) | 0;
    Ja = (bc + 16) | 0;
    Ka = ($b + 16) | 0;
    La = (bc + 20) | 0;
    Ma = ($b + 20) | 0;
    Na = (bc + 24) | 0;
    Pa = ($b + 24) | 0;
    Qa = (bc + 28) | 0;
    Ra = ($b + 28) | 0;
    Ta = (bc + 32) | 0;
    Wa = ($b + 32) | 0;
    Xa = (bc + 36) | 0;
    Ya = ($b + 36) | 0;
    Za = (Wb + 4) | 0;
    _a = (Wb + 8) | 0;
    ab = (Wb + 12) | 0;
    cb = (Wb + 16) | 0;
    db = (Wb + 20) | 0;
    eb = (Wb + 24) | 0;
    fb = (Wb + 28) | 0;
    gb = (Wb + 32) | 0;
    hb = (Wb + 36) | 0;
    ib = (_b + 4) | 0;
    jb = (_b + 8) | 0;
    kb = (_b + 12) | 0;
    lb = (_b + 16) | 0;
    nb = (_b + 20) | 0;
    ob = (_b + 24) | 0;
    pb = (_b + 28) | 0;
    qb = (_b + 32) | 0;
    rb = (_b + 36) | 0;
    sb = (Zb + 4) | 0;
    tb = (Zb + 8) | 0;
    ub = (Zb + 12) | 0;
    vb = (Zb + 16) | 0;
    wb = (Zb + 20) | 0;
    yb = (Zb + 24) | 0;
    zb = (Zb + 28) | 0;
    Ab = (Zb + 32) | 0;
    Bb = (Zb + 36) | 0;
    Cb = (a + 84) | 0;
    Db = (a + 88) | 0;
    Eb = (a + 92) | 0;
    Fb = (a + 96) | 0;
    Gb = (a + 100) | 0;
    Hb = (a + 104) | 0;
    Jb = (a + 108) | 0;
    Kb = (a + 112) | 0;
    Lb = (a + 116) | 0;
    Mb = (Yb + 4) | 0;
    Nb = (Yb + 8) | 0;
    Ob = (Yb + 12) | 0;
    Pb = (Yb + 16) | 0;
    Qb = (Yb + 20) | 0;
    Rb = (Yb + 24) | 0;
    Sb = (Yb + 28) | 0;
    G = (Yb + 32) | 0;
    H = (Yb + 36) | 0;
    I = (a + 4) | 0;
    J = (a + 8) | 0;
    K = (a + 12) | 0;
    L = (a + 16) | 0;
    M = (a + 20) | 0;
    N = (a + 24) | 0;
    O = (a + 28) | 0;
    P = (a + 32) | 0;
    R = (a + 36) | 0;
    S = (Xb + 4) | 0;
    T = (Xb + 8) | 0;
    U = (Xb + 12) | 0;
    V = (Xb + 16) | 0;
    W = (Xb + 20) | 0;
    X = (Xb + 24) | 0;
    Y = (Xb + 28) | 0;
    Z = (Xb + 32) | 0;
    _ = (Xb + 36) | 0;
    Vb = 0;
    do {
      n =
        ((c[(b + (((Vb >>> 3) & 134217727) << 2)) >> 2] | 0) >>>
          ((Vb << 2) & 28)) &
        15;
      m = c[Ub >> 2] | 0;
      l = c[sa >> 2] | 0;
      k = c[Da >> 2] | 0;
      j = c[Oa >> 2] | 0;
      h = c[bb >> 2] | 0;
      g = c[mb >> 2] | 0;
      f = c[xb >> 2] | 0;
      e = c[Ib >> 2] | 0;
      d = c[F >> 2] | 0;
      o = c[Q >> 2] | 0;
      p = c[$ >> 2] | 0;
      q = c[ba >> 2] | 0;
      r = c[ca >> 2] | 0;
      s = c[da >> 2] | 0;
      t = c[ea >> 2] | 0;
      u = c[fa >> 2] | 0;
      v = 0;
      do {
        C = (v | 0) == (n | 0);
        m = C ? c[(D + (Vb << 10) + (v << 6)) >> 2] | 0 : m;
        l = C ? c[(D + (Vb << 10) + (v << 6) + 4) >> 2] | 0 : l;
        k = C ? c[(D + (Vb << 10) + (v << 6) + 8) >> 2] | 0 : k;
        j = C ? c[(D + (Vb << 10) + (v << 6) + 12) >> 2] | 0 : j;
        h = C ? c[(D + (Vb << 10) + (v << 6) + 16) >> 2] | 0 : h;
        g = C ? c[(D + (Vb << 10) + (v << 6) + 20) >> 2] | 0 : g;
        f = C ? c[(D + (Vb << 10) + (v << 6) + 24) >> 2] | 0 : f;
        e = C ? c[(D + (Vb << 10) + (v << 6) + 28) >> 2] | 0 : e;
        d = C ? c[(D + (Vb << 10) + (v << 6) + 32) >> 2] | 0 : d;
        o = C ? c[(D + (Vb << 10) + (v << 6) + 36) >> 2] | 0 : o;
        p = C ? c[(D + (Vb << 10) + (v << 6) + 40) >> 2] | 0 : p;
        q = C ? c[(D + (Vb << 10) + (v << 6) + 44) >> 2] | 0 : q;
        r = C ? c[(D + (Vb << 10) + (v << 6) + 48) >> 2] | 0 : r;
        s = C ? c[(D + (Vb << 10) + (v << 6) + 52) >> 2] | 0 : s;
        t = C ? c[(D + (Vb << 10) + (v << 6) + 56) >> 2] | 0 : t;
        u = C ? c[(D + (Vb << 10) + (v << 6) + 60) >> 2] | 0 : u;
        v = (v + 1) | 0;
      } while ((v | 0) != 16);
      c[Ub >> 2] = m;
      c[sa >> 2] = l;
      c[Da >> 2] = k;
      c[Oa >> 2] = j;
      c[bb >> 2] = h;
      c[mb >> 2] = g;
      c[xb >> 2] = f;
      c[Ib >> 2] = e;
      c[F >> 2] = d;
      c[Q >> 2] = o;
      c[$ >> 2] = p;
      c[ba >> 2] = q;
      c[ca >> 2] = r;
      c[da >> 2] = s;
      c[ea >> 2] = t;
      c[fa >> 2] = u;
      Sa(Tb, Ub);
      Ua(dc, ga);
      A = (ac + 0) | 0;
      B = (a + 0) | 0;
      C = (A + 40) | 0;
      do {
        c[A >> 2] = c[B >> 2];
        A = (A + 4) | 0;
        B = (B + 4) | 0;
      } while ((A | 0) < (C | 0));
      m = c[pa >> 2] | 0;
      l = m >>> 22;
      n = (((l * 977) | 0) + (c[ac >> 2] | 0)) | 0;
      l = ((l << 6) + (c[ha >> 2] | 0) + (n >>> 26)) | 0;
      k = ((l >>> 26) + (c[ia >> 2] | 0)) | 0;
      j = ((k >>> 26) + (c[ja >> 2] | 0)) | 0;
      h = ((j >>> 26) + (c[ka >> 2] | 0)) | 0;
      g = ((h >>> 26) + (c[la >> 2] | 0)) | 0;
      f = ((g >>> 26) + (c[ma >> 2] | 0)) | 0;
      d = ((f >>> 26) + (c[na >> 2] | 0)) | 0;
      e = ((d >>> 26) + (c[oa >> 2] | 0)) | 0;
      c[ac >> 2] = n & 67108863;
      c[ha >> 2] = l & 67108863;
      c[ia >> 2] = k & 67108863;
      c[ja >> 2] = j & 67108863;
      c[ka >> 2] = h & 67108863;
      c[la >> 2] = g & 67108863;
      c[ma >> 2] = f & 67108863;
      c[na >> 2] = d & 67108863;
      c[oa >> 2] = e & 67108863;
      c[pa >> 2] = (e >>> 26) + (m & 4194303);
      Va(bc, Tb, dc);
      m = c[Aa >> 2] | 0;
      e = m >>> 22;
      d = (((e * 977) | 0) + (c[qa >> 2] | 0)) | 0;
      e = ((e << 6) + (c[ra >> 2] | 0) + (d >>> 26)) | 0;
      d = d & 67108863;
      f = ((e >>> 26) + (c[ta >> 2] | 0)) | 0;
      e = e & 67108863;
      g = ((f >>> 26) + (c[ua >> 2] | 0)) | 0;
      f = f & 67108863;
      h = ((g >>> 26) + (c[va >> 2] | 0)) | 0;
      g = g & 67108863;
      j = ((h >>> 26) + (c[wa >> 2] | 0)) | 0;
      h = h & 67108863;
      k = ((j >>> 26) + (c[xa >> 2] | 0)) | 0;
      j = j & 67108863;
      l = ((k >>> 26) + (c[ya >> 2] | 0)) | 0;
      k = k & 67108863;
      n = ((l >>> 26) + (c[za >> 2] | 0)) | 0;
      l = l & 67108863;
      m = ((n >>> 26) + (m & 4194303)) | 0;
      n = n & 67108863;
      Va(_b, Ba, dc);
      Va(_b, _b, ga);
      A = (cc + 0) | 0;
      B = (ga + 0) | 0;
      C = (A + 40) | 0;
      do {
        c[A >> 2] = c[B >> 2];
        A = (A + 4) | 0;
        B = (B + 4) | 0;
      } while ((A | 0) < (C | 0));
      A = ($b + 0) | 0;
      B = (ac + 0) | 0;
      C = (A + 40) | 0;
      do {
        c[A >> 2] = c[B >> 2];
        A = (A + 4) | 0;
        B = (B + 4) | 0;
      } while ((A | 0) < (C | 0));
      c[$b >> 2] = (c[$b >> 2] | 0) + (c[bc >> 2] | 0);
      c[Ea >> 2] = (c[Ea >> 2] | 0) + (c[Ca >> 2] | 0);
      c[Ga >> 2] = (c[Ga >> 2] | 0) + (c[Fa >> 2] | 0);
      c[Ia >> 2] = (c[Ia >> 2] | 0) + (c[Ha >> 2] | 0);
      c[Ka >> 2] = (c[Ka >> 2] | 0) + (c[Ja >> 2] | 0);
      c[Ma >> 2] = (c[Ma >> 2] | 0) + (c[La >> 2] | 0);
      c[Pa >> 2] = (c[Pa >> 2] | 0) + (c[Na >> 2] | 0);
      c[Ra >> 2] = (c[Ra >> 2] | 0) + (c[Qa >> 2] | 0);
      c[Wa >> 2] = (c[Wa >> 2] | 0) + (c[Ta >> 2] | 0);
      c[Ya >> 2] = (c[Ya >> 2] | 0) + (c[Xa >> 2] | 0);
      c[Wb >> 2] = (c[_b >> 2] | 0) + d;
      c[Za >> 2] = (c[ib >> 2] | 0) + e;
      c[_a >> 2] = (c[jb >> 2] | 0) + f;
      c[ab >> 2] = (c[kb >> 2] | 0) + g;
      c[cb >> 2] = (c[lb >> 2] | 0) + h;
      c[db >> 2] = (c[nb >> 2] | 0) + j;
      c[eb >> 2] = (c[ob >> 2] | 0) + k;
      c[fb >> 2] = (c[pb >> 2] | 0) + l;
      c[gb >> 2] = (c[qb >> 2] | 0) + n;
      c[hb >> 2] = m + (c[rb >> 2] | 0);
      Ua(Xb, Wb);
      Va(Yb, Xb, $b);
      Ua(Xb, Xb);
      Ua(Zb, $b);
      Va($b, ac, bc);
      A = (268431548 - (c[$b >> 2] | 0)) | 0;
      c[$b >> 2] = A;
      C = (268435196 - (c[Ea >> 2] | 0)) | 0;
      c[Ea >> 2] = C;
      z = (268435452 - (c[Ga >> 2] | 0)) | 0;
      c[Ga >> 2] = z;
      y = (268435452 - (c[Ia >> 2] | 0)) | 0;
      c[Ia >> 2] = y;
      x = (268435452 - (c[Ka >> 2] | 0)) | 0;
      c[Ka >> 2] = x;
      w = (268435452 - (c[Ma >> 2] | 0)) | 0;
      c[Ma >> 2] = w;
      u = (268435452 - (c[Pa >> 2] | 0)) | 0;
      c[Pa >> 2] = u;
      t = (268435452 - (c[Ra >> 2] | 0)) | 0;
      c[Ra >> 2] = t;
      s = (268435452 - (c[Wa >> 2] | 0)) | 0;
      c[Wa >> 2] = s;
      r = (16777212 - (c[Ya >> 2] | 0)) | 0;
      c[Ya >> 2] = r;
      c[Zb >> 2] = (c[Zb >> 2] | 0) + A;
      c[sb >> 2] = (c[sb >> 2] | 0) + C;
      c[tb >> 2] = (c[tb >> 2] | 0) + z;
      c[ub >> 2] = (c[ub >> 2] | 0) + y;
      c[vb >> 2] = (c[vb >> 2] | 0) + x;
      c[wb >> 2] = (c[wb >> 2] | 0) + w;
      c[yb >> 2] = (c[yb >> 2] | 0) + u;
      c[zb >> 2] = (c[zb >> 2] | 0) + t;
      c[Ab >> 2] = (c[Ab >> 2] | 0) + s;
      c[Bb >> 2] = (c[Bb >> 2] | 0) + r;
      Ua($b, Zb);
      Va(ga, Wb, cc);
      r = c[ga >> 2] | 0;
      s = c[Cb >> 2] | 0;
      t = c[Db >> 2] | 0;
      u = c[Eb >> 2] | 0;
      w = c[Fb >> 2] | 0;
      x = c[Gb >> 2] | 0;
      y = c[Hb >> 2] | 0;
      z = c[Jb >> 2] | 0;
      C = c[Kb >> 2] | 0;
      A = c[Lb >> 2] | 0;
      h = A >>> 22;
      j = (((h * 977) | 0) + r) | 0;
      h = ((h << 6) + s + (j >>> 26)) | 0;
      k = ((h >>> 26) + t) | 0;
      l = ((k >>> 26) + u) | 0;
      m = ((l >>> 26) + w) | 0;
      n = ((m >>> 26) + x) | 0;
      o = ((n >>> 26) + y) | 0;
      p = ((o >>> 26) + z) | 0;
      o = o & 67108863;
      q = ((p >>> 26) + C) | 0;
      v = ((q >>> 26) + (A & 4194303)) | 0;
      B = (1 - (c[E >> 2] | 0)) | 0;
      v =
        B &
        (0 -
          ((o |
            ((h | j | k | l | m | n) & 67108863) |
            (p & 67108863) |
            (q & 67108863) |
            v |
            0) ==
          0
            ? 1
            : (((h ^ 64) &
                (j ^ 976) &
                k &
                l &
                m &
                n &
                o &
                p &
                q &
                (v ^ 62914560)) |
                0) ==
              67108863));
      B = B << 1;
      c[ga >> 2] = aa(B, r) | 0;
      c[Cb >> 2] = aa(B, s) | 0;
      c[Db >> 2] = aa(B, t) | 0;
      c[Eb >> 2] = aa(B, u) | 0;
      c[Fb >> 2] = aa(B, w) | 0;
      c[Gb >> 2] = aa(B, x) | 0;
      c[Hb >> 2] = aa(B, y) | 0;
      c[Jb >> 2] = aa(B, z) | 0;
      c[Kb >> 2] = aa(B, C) | 0;
      c[Lb >> 2] = aa(B, A) | 0;
      A = (a + 0) | 0;
      B = ($b + 0) | 0;
      C = (A + 40) | 0;
      do {
        c[A >> 2] = c[B >> 2];
        A = (A + 4) | 0;
        B = (B + 4) | 0;
      } while ((A | 0) < (C | 0));
      n = (268431548 - (c[Yb >> 2] | 0)) | 0;
      p = (268435196 - (c[Mb >> 2] | 0)) | 0;
      r = (268435452 - (c[Nb >> 2] | 0)) | 0;
      t = (268435452 - (c[Ob >> 2] | 0)) | 0;
      h = (268435452 - (c[Pb >> 2] | 0)) | 0;
      B = (268435452 - (c[Qb >> 2] | 0)) | 0;
      w = (268435452 - (c[Rb >> 2] | 0)) | 0;
      e = (268435452 - (c[Sb >> 2] | 0)) | 0;
      g = (268435452 - (c[G >> 2] | 0)) | 0;
      j = (16777212 - (c[H >> 2] | 0)) | 0;
      c[a >> 2] = (c[a >> 2] | 0) + n;
      c[I >> 2] = (c[I >> 2] | 0) + p;
      c[J >> 2] = (c[J >> 2] | 0) + r;
      c[K >> 2] = (c[K >> 2] | 0) + t;
      c[L >> 2] = (c[L >> 2] | 0) + h;
      c[M >> 2] = (c[M >> 2] | 0) + B;
      c[N >> 2] = (c[N >> 2] | 0) + w;
      c[O >> 2] = (c[O >> 2] | 0) + e;
      c[P >> 2] = (c[P >> 2] | 0) + g;
      c[R >> 2] = (c[R >> 2] | 0) + j;
      $a(a);
      n = (n * 3) | 0;
      c[Yb >> 2] = n;
      p = (p * 3) | 0;
      c[Mb >> 2] = p;
      r = (r * 3) | 0;
      c[Nb >> 2] = r;
      t = (t * 3) | 0;
      c[Ob >> 2] = t;
      h = (h * 3) | 0;
      c[Pb >> 2] = h;
      B = (B * 3) | 0;
      c[Qb >> 2] = B;
      w = (w * 3) | 0;
      c[Rb >> 2] = w;
      e = (e * 3) | 0;
      c[Sb >> 2] = e;
      g = (g * 3) | 0;
      c[G >> 2] = g;
      j = (j * 3) | 0;
      c[H >> 2] = j;
      o = c[Ea >> 2] << 1;
      q = c[Ga >> 2] << 1;
      s = c[Ia >> 2] << 1;
      z = c[Ka >> 2] << 1;
      A = c[Ma >> 2] << 1;
      x = c[Pa >> 2] << 1;
      d = c[Ra >> 2] << 1;
      f = c[Wa >> 2] << 1;
      u = c[Ya >> 2] << 1;
      c[$b >> 2] = (c[$b >> 2] << 1) + n;
      c[Ea >> 2] = o + p;
      c[Ga >> 2] = q + r;
      c[Ia >> 2] = s + t;
      c[Ka >> 2] = z + h;
      c[Ma >> 2] = A + B;
      c[Pa >> 2] = x + w;
      c[Ra >> 2] = d + e;
      c[Wa >> 2] = f + g;
      c[Ya >> 2] = u + j;
      Va($b, $b, Zb);
      j = ((c[$b >> 2] | 0) + (c[Xb >> 2] | 0)) | 0;
      c[$b >> 2] = j;
      u = ((c[Ea >> 2] | 0) + (c[S >> 2] | 0)) | 0;
      c[Ea >> 2] = u;
      g = ((c[Ga >> 2] | 0) + (c[T >> 2] | 0)) | 0;
      c[Ga >> 2] = g;
      f = ((c[Ia >> 2] | 0) + (c[U >> 2] | 0)) | 0;
      c[Ia >> 2] = f;
      e = ((c[Ka >> 2] | 0) + (c[V >> 2] | 0)) | 0;
      c[Ka >> 2] = e;
      d = ((c[Ma >> 2] | 0) + (c[W >> 2] | 0)) | 0;
      c[Ma >> 2] = d;
      w = ((c[Pa >> 2] | 0) + (c[X >> 2] | 0)) | 0;
      c[Pa >> 2] = w;
      x = ((c[Ra >> 2] | 0) + (c[Y >> 2] | 0)) | 0;
      c[Ra >> 2] = x;
      B = ((c[Wa >> 2] | 0) + (c[Z >> 2] | 0)) | 0;
      c[Wa >> 2] = B;
      A = (25165818 - ((c[Ya >> 2] | 0) + (c[_ >> 2] | 0))) | 0;
      h = A >>> 22;
      j = (((h * 977) | 0) + (402647322 - j)) | 0;
      h = (402652794 - u + (h << 6) + (j >>> 26)) | 0;
      g = ((h >>> 26) + (402653178 - g)) | 0;
      f = ((g >>> 26) + (402653178 - f)) | 0;
      e = ((f >>> 26) + (402653178 - e)) | 0;
      d = ((e >>> 26) + (402653178 - d)) | 0;
      w = ((d >>> 26) + (402653178 - w)) | 0;
      x = ((w >>> 26) + (402653178 - x)) | 0;
      B = ((x >>> 26) + (402653178 - B)) | 0;
      u = c[E >> 2] | 0;
      z = (1 - u) << 2;
      t = aa(z, c[a >> 2] | 0) | 0;
      s = aa(c[I >> 2] | 0, z) | 0;
      r = aa(c[J >> 2] | 0, z) | 0;
      q = aa(c[K >> 2] | 0, z) | 0;
      p = aa(c[L >> 2] | 0, z) | 0;
      o = aa(c[M >> 2] | 0, z) | 0;
      n = aa(c[N >> 2] | 0, z) | 0;
      m = aa(c[O >> 2] | 0, z) | 0;
      l = aa(c[P >> 2] | 0, z) | 0;
      k = aa(c[R >> 2] | 0, z) | 0;
      j = aa(z, j & 67108863) | 0;
      c[qa >> 2] = j;
      h = aa(z, h & 67108863) | 0;
      c[ra >> 2] = h;
      g = aa(z, g & 67108863) | 0;
      c[ta >> 2] = g;
      f = aa(z, f & 67108863) | 0;
      c[ua >> 2] = f;
      e = aa(e & 67108863, z) | 0;
      c[va >> 2] = e;
      d = aa(d & 67108863, z) | 0;
      c[wa >> 2] = d;
      w = aa(w & 67108863, z) | 0;
      c[xa >> 2] = w;
      x = aa(x & 67108863, z) | 0;
      c[ya >> 2] = x;
      y = aa(B & 67108863, z) | 0;
      c[za >> 2] = y;
      z = aa(((B >>> 26) + (A & 4194303)) | 0, z) | 0;
      c[Aa >> 2] = z;
      A = ($b + 0) | 0;
      B = (Tb + 0) | 0;
      C = (A + 40) | 0;
      do {
        c[A >> 2] = c[B >> 2];
        A = (A + 4) | 0;
        B = (B + 4) | 0;
      } while ((A | 0) < (C | 0));
      lc = aa(c[$b >> 2] | 0, u) | 0;
      c[$b >> 2] = lc;
      kc = aa(c[Ea >> 2] | 0, u) | 0;
      c[Ea >> 2] = kc;
      jc = aa(c[Ga >> 2] | 0, u) | 0;
      c[Ga >> 2] = jc;
      ic = aa(c[Ia >> 2] | 0, u) | 0;
      c[Ia >> 2] = ic;
      hc = aa(c[Ka >> 2] | 0, u) | 0;
      c[Ka >> 2] = hc;
      gc = aa(c[Ma >> 2] | 0, u) | 0;
      c[Ma >> 2] = gc;
      fc = aa(c[Pa >> 2] | 0, u) | 0;
      c[Pa >> 2] = fc;
      C = aa(c[Ra >> 2] | 0, u) | 0;
      c[Ra >> 2] = C;
      B = aa(c[Wa >> 2] | 0, u) | 0;
      c[Wa >> 2] = B;
      A = aa(c[Ya >> 2] | 0, u) | 0;
      c[a >> 2] = lc + t;
      c[I >> 2] = kc + s;
      c[J >> 2] = jc + r;
      c[K >> 2] = ic + q;
      c[L >> 2] = hc + p;
      c[M >> 2] = gc + o;
      c[N >> 2] = fc + n;
      c[O >> 2] = C + m;
      c[P >> 2] = B + l;
      c[R >> 2] = A + k;
      A = ($b + 0) | 0;
      B = (Ba + 0) | 0;
      C = (A + 40) | 0;
      do {
        c[A >> 2] = c[B >> 2];
        A = (A + 4) | 0;
        B = (B + 4) | 0;
      } while ((A | 0) < (C | 0));
      lc = c[E >> 2] | 0;
      u = aa(c[$b >> 2] | 0, lc) | 0;
      A = aa(c[Ea >> 2] | 0, lc) | 0;
      c[Ea >> 2] = A;
      B = aa(c[Ga >> 2] | 0, lc) | 0;
      c[Ga >> 2] = B;
      C = aa(c[Ia >> 2] | 0, lc) | 0;
      c[Ia >> 2] = C;
      fc = aa(c[Ka >> 2] | 0, lc) | 0;
      c[Ka >> 2] = fc;
      gc = aa(c[Ma >> 2] | 0, lc) | 0;
      c[Ma >> 2] = gc;
      hc = aa(c[Pa >> 2] | 0, lc) | 0;
      c[Pa >> 2] = hc;
      ic = aa(c[Ra >> 2] | 0, lc) | 0;
      c[Ra >> 2] = ic;
      jc = aa(c[Wa >> 2] | 0, lc) | 0;
      c[Wa >> 2] = jc;
      kc = aa(c[Ya >> 2] | 0, lc) | 0;
      c[qa >> 2] = j + u;
      c[ra >> 2] = h + A;
      c[ta >> 2] = g + B;
      c[ua >> 2] = f + C;
      c[va >> 2] = e + fc;
      c[wa >> 2] = d + gc;
      c[xa >> 2] = w + hc;
      c[ya >> 2] = x + ic;
      c[za >> 2] = y + jc;
      c[Aa >> 2] = z + kc;
      c[ga >> 2] = (c[ga >> 2] | 0) + lc;
      c[E >> 2] = v;
      Vb = (Vb + 1) | 0;
    } while ((Vb | 0) != 64);
    i = ec;
    return;
  }
  function Qa(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0,
      N = 0,
      O = 0,
      P = 0,
      Q = 0,
      R = 0,
      S = 0,
      T = 0,
      U = 0,
      V = 0,
      W = 0,
      X = 0,
      Y = 0,
      Z = 0,
      _ = 0,
      $ = 0;
    C = i;
    i = (i + 160) | 0;
    y = (C + 120) | 0;
    z = (C + 80) | 0;
    A = (C + 40) | 0;
    B = C;
    x = c[(b + 120) >> 2] | 0;
    c[(a + 120) >> 2] = x;
    if (x) {
      i = C;
      return;
    }
    o = (a + 80) | 0;
    n = (b + 40) | 0;
    Va(o, (b + 80) | 0, n);
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 84) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 88) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 92) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 96) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 100) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 104) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 108) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 112) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    o = (a + 116) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    Ua(y, b);
    c[y >> 2] = (c[y >> 2] | 0) * 3;
    o = (y + 4) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 8) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 12) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 16) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 20) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 24) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 28) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 32) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    o = (y + 36) | 0;
    c[o >> 2] = (c[o >> 2] | 0) * 3;
    Ua(z, y);
    Ua(A, n);
    c[A >> 2] = c[A >> 2] << 1;
    n = (A + 4) | 0;
    c[n >> 2] = c[n >> 2] << 1;
    o = (A + 8) | 0;
    c[o >> 2] = c[o >> 2] << 1;
    p = (A + 12) | 0;
    c[p >> 2] = c[p >> 2] << 1;
    q = (A + 16) | 0;
    c[q >> 2] = c[q >> 2] << 1;
    r = (A + 20) | 0;
    c[r >> 2] = c[r >> 2] << 1;
    s = (A + 24) | 0;
    c[s >> 2] = c[s >> 2] << 1;
    t = (A + 28) | 0;
    c[t >> 2] = c[t >> 2] << 1;
    u = (A + 32) | 0;
    c[u >> 2] = c[u >> 2] << 1;
    v = (A + 36) | 0;
    c[v >> 2] = c[v >> 2] << 1;
    Ua(B, A);
    c[B >> 2] = c[B >> 2] << 1;
    w = (B + 4) | 0;
    c[w >> 2] = c[w >> 2] << 1;
    x = (B + 8) | 0;
    c[x >> 2] = c[x >> 2] << 1;
    f = (B + 12) | 0;
    c[f >> 2] = c[f >> 2] << 1;
    g = (B + 16) | 0;
    c[g >> 2] = c[g >> 2] << 1;
    h = (B + 20) | 0;
    c[h >> 2] = c[h >> 2] << 1;
    j = (B + 24) | 0;
    c[j >> 2] = c[j >> 2] << 1;
    k = (B + 28) | 0;
    c[k >> 2] = c[k >> 2] << 1;
    l = (B + 32) | 0;
    c[l >> 2] = c[l >> 2] << 1;
    m = (B + 36) | 0;
    c[m >> 2] = c[m >> 2] << 1;
    Va(A, A, b);
    b = (a + 0) | 0;
    d = (A + 0) | 0;
    e = (b + 40) | 0;
    do {
      c[b >> 2] = c[d >> 2];
      b = (b + 4) | 0;
      d = (d + 4) | 0;
    } while ((b | 0) < (e | 0));
    H = (a + 4) | 0;
    G = (a + 8) | 0;
    F = (a + 12) | 0;
    E = (a + 16) | 0;
    D = (a + 20) | 0;
    b = (a + 24) | 0;
    d = (a + 28) | 0;
    e = (a + 32) | 0;
    _ = (a + 36) | 0;
    X = (671087990 - (c[H >> 2] << 2)) | 0;
    V = (671088630 - (c[G >> 2] << 2)) | 0;
    T = (671088630 - (c[F >> 2] << 2)) | 0;
    R = (671088630 - (c[E >> 2] << 2)) | 0;
    P = (671088630 - (c[D >> 2] << 2)) | 0;
    N = (671088630 - (c[b >> 2] << 2)) | 0;
    L = (671088630 - (c[d >> 2] << 2)) | 0;
    J = (671088630 - (c[e >> 2] << 2)) | 0;
    Y = (41943030 - (c[_ >> 2] << 2)) | 0;
    $ = c[z >> 2] | 0;
    c[a >> 2] = 671078870 - (c[a >> 2] << 2) + $;
    I = (z + 4) | 0;
    Z = c[I >> 2] | 0;
    c[H >> 2] = X + Z;
    H = (z + 8) | 0;
    X = c[H >> 2] | 0;
    c[G >> 2] = V + X;
    G = (z + 12) | 0;
    V = c[G >> 2] | 0;
    c[F >> 2] = T + V;
    F = (z + 16) | 0;
    T = c[F >> 2] | 0;
    c[E >> 2] = R + T;
    E = (z + 20) | 0;
    R = c[E >> 2] | 0;
    c[D >> 2] = P + R;
    D = (z + 24) | 0;
    P = c[D >> 2] | 0;
    c[b >> 2] = N + P;
    b = (z + 28) | 0;
    N = c[b >> 2] | 0;
    c[d >> 2] = L + N;
    d = (z + 32) | 0;
    L = c[d >> 2] | 0;
    c[e >> 2] = J + L;
    e = (z + 36) | 0;
    J = c[e >> 2] | 0;
    c[_ >> 2] = Y + J;
    _ = ((c[n >> 2] | 0) * 6) | 0;
    Y = ((c[o >> 2] | 0) * 6) | 0;
    W = ((c[p >> 2] | 0) * 6) | 0;
    U = ((c[q >> 2] | 0) * 6) | 0;
    S = ((c[r >> 2] | 0) * 6) | 0;
    Q = ((c[s >> 2] | 0) * 6) | 0;
    O = ((c[t >> 2] | 0) * 6) | 0;
    M = ((c[u >> 2] | 0) * 6) | 0;
    K = ((c[v >> 2] | 0) * 6) | 0;
    c[A >> 2] = (((c[A >> 2] | 0) * 6) | 0) + (268431548 - $);
    c[n >> 2] = _ + (268435196 - Z);
    c[o >> 2] = Y + (268435452 - X);
    c[p >> 2] = W + (268435452 - V);
    c[q >> 2] = U + (268435452 - T);
    c[r >> 2] = S + (268435452 - R);
    c[s >> 2] = Q + (268435452 - P);
    c[t >> 2] = O + (268435452 - N);
    c[u >> 2] = M + (268435452 - L);
    c[v >> 2] = K + (16777212 - J);
    r = (a + 40) | 0;
    Va(r, y, A);
    B = (402647322 - (c[B >> 2] | 0)) | 0;
    c[z >> 2] = B;
    s = (402652794 - (c[w >> 2] | 0)) | 0;
    c[I >> 2] = s;
    t = (402653178 - (c[x >> 2] | 0)) | 0;
    c[H >> 2] = t;
    u = (402653178 - (c[f >> 2] | 0)) | 0;
    c[G >> 2] = u;
    v = (402653178 - (c[g >> 2] | 0)) | 0;
    c[F >> 2] = v;
    w = (402653178 - (c[h >> 2] | 0)) | 0;
    c[E >> 2] = w;
    x = (402653178 - (c[j >> 2] | 0)) | 0;
    c[D >> 2] = x;
    y = (402653178 - (c[k >> 2] | 0)) | 0;
    c[b >> 2] = y;
    z = (402653178 - (c[l >> 2] | 0)) | 0;
    c[d >> 2] = z;
    A = (25165818 - (c[m >> 2] | 0)) | 0;
    c[e >> 2] = A;
    c[r >> 2] = (c[r >> 2] | 0) + B;
    B = (a + 44) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + s;
    B = (a + 48) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + t;
    B = (a + 52) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + u;
    B = (a + 56) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + v;
    B = (a + 60) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + w;
    B = (a + 64) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + x;
    B = (a + 68) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + y;
    B = (a + 72) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + z;
    B = (a + 76) | 0;
    c[B >> 2] = (c[B >> 2] | 0) + A;
    i = C;
    return;
  }
  function Ra(a, b, d) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0;
    u = i;
    i = (i + 480) | 0;
    o = (u + 40) | 0;
    n = (u + 160) | 0;
    l = (u + 360) | 0;
    m = u;
    s = (u + 320) | 0;
    k = (u + 400) | 0;
    h = (u + 440) | 0;
    q = (u + 240) | 0;
    r = (u + 200) | 0;
    j = (u + 80) | 0;
    p = (u + 120) | 0;
    t = (u + 280) | 0;
    if (c[(b + 120) >> 2] | 0) {
      g = (a + 0) | 0;
      e = (d + 0) | 0;
      f = (g + 124) | 0;
      do {
        c[g >> 2] = c[e >> 2];
        g = (g + 4) | 0;
        e = (e + 4) | 0;
      } while ((g | 0) < (f | 0));
      i = u;
      return;
    }
    if (c[(d + 120) >> 2] | 0) {
      g = (a + 0) | 0;
      e = (b + 0) | 0;
      f = (g + 124) | 0;
      do {
        c[g >> 2] = c[e >> 2];
        g = (g + 4) | 0;
        e = (e + 4) | 0;
      } while ((g | 0) < (f | 0));
      i = u;
      return;
    }
    g = (a + 120) | 0;
    c[g >> 2] = 0;
    f = (d + 80) | 0;
    Ua(o, f);
    e = (b + 80) | 0;
    Ua(n, e);
    Va(l, b, o);
    Va(m, d, n);
    Va(s, (b + 40) | 0, o);
    Va(s, s, f);
    Va(k, (d + 40) | 0, n);
    Va(k, k, e);
    A = (268435196 - (c[(l + 4) >> 2] | 0)) | 0;
    d = (268435452 - (c[(l + 8) >> 2] | 0)) | 0;
    o = (268435452 - (c[(l + 12) >> 2] | 0)) | 0;
    n = (268435452 - (c[(l + 16) >> 2] | 0)) | 0;
    v = (268435452 - (c[(l + 20) >> 2] | 0)) | 0;
    w = (268435452 - (c[(l + 24) >> 2] | 0)) | 0;
    x = (268435452 - (c[(l + 28) >> 2] | 0)) | 0;
    y = (268435452 - (c[(l + 32) >> 2] | 0)) | 0;
    z = (16777212 - (c[(l + 36) >> 2] | 0)) | 0;
    c[h >> 2] = 268431548 - (c[l >> 2] | 0) + (c[m >> 2] | 0);
    c[(h + 4) >> 2] = A + (c[(m + 4) >> 2] | 0);
    c[(h + 8) >> 2] = d + (c[(m + 8) >> 2] | 0);
    c[(h + 12) >> 2] = o + (c[(m + 12) >> 2] | 0);
    c[(h + 16) >> 2] = n + (c[(m + 16) >> 2] | 0);
    c[(h + 20) >> 2] = v + (c[(m + 20) >> 2] | 0);
    c[(h + 24) >> 2] = w + (c[(m + 24) >> 2] | 0);
    c[(h + 28) >> 2] = x + (c[(m + 28) >> 2] | 0);
    c[(h + 32) >> 2] = y + (c[(m + 32) >> 2] | 0);
    c[(h + 36) >> 2] = z + (c[(m + 36) >> 2] | 0);
    z = (268435196 - (c[(s + 4) >> 2] | 0)) | 0;
    y = (268435452 - (c[(s + 8) >> 2] | 0)) | 0;
    x = (268435452 - (c[(s + 12) >> 2] | 0)) | 0;
    w = (268435452 - (c[(s + 16) >> 2] | 0)) | 0;
    v = (268435452 - (c[(s + 20) >> 2] | 0)) | 0;
    m = (268435452 - (c[(s + 24) >> 2] | 0)) | 0;
    n = (268435452 - (c[(s + 28) >> 2] | 0)) | 0;
    o = (268435452 - (c[(s + 32) >> 2] | 0)) | 0;
    d = (16777212 - (c[(s + 36) >> 2] | 0)) | 0;
    c[q >> 2] = 268431548 - (c[s >> 2] | 0) + (c[k >> 2] | 0);
    c[(q + 4) >> 2] = z + (c[(k + 4) >> 2] | 0);
    c[(q + 8) >> 2] = y + (c[(k + 8) >> 2] | 0);
    c[(q + 12) >> 2] = x + (c[(k + 12) >> 2] | 0);
    c[(q + 16) >> 2] = w + (c[(k + 16) >> 2] | 0);
    c[(q + 20) >> 2] = v + (c[(k + 20) >> 2] | 0);
    c[(q + 24) >> 2] = m + (c[(k + 24) >> 2] | 0);
    c[(q + 28) >> 2] = n + (c[(k + 28) >> 2] | 0);
    c[(q + 32) >> 2] = o + (c[(k + 32) >> 2] | 0);
    c[(q + 36) >> 2] = d + (c[(k + 36) >> 2] | 0);
    if (!(Wa(h) | 0)) {
      Ua(r, q);
      Ua(j, h);
      Va(p, h, j);
      g = (a + 80) | 0;
      Va(g, e, f);
      Va(g, g, h);
      Va(t, l, j);
      g = (a + 0) | 0;
      e = (t + 0) | 0;
      f = (g + 40) | 0;
      do {
        c[g >> 2] = c[e >> 2];
        g = (g + 4) | 0;
        e = (e + 4) | 0;
      } while ((g | 0) < (f | 0));
      A = (a + 4) | 0;
      y = (a + 8) | 0;
      w = (a + 12) | 0;
      d = (a + 16) | 0;
      b = (a + 20) | 0;
      o = (a + 24) | 0;
      n = (a + 28) | 0;
      m = (a + 32) | 0;
      k = (a + 36) | 0;
      C = (p + 4) | 0;
      B = (p + 8) | 0;
      e = (p + 12) | 0;
      f = (p + 16) | 0;
      g = (p + 20) | 0;
      v = (p + 24) | 0;
      x = (p + 28) | 0;
      z = (p + 32) | 0;
      h = (p + 36) | 0;
      J = (536870392 - ((c[A >> 2] << 1) + (c[C >> 2] | 0))) | 0;
      I = (536870904 - ((c[y >> 2] << 1) + (c[B >> 2] | 0))) | 0;
      H = (536870904 - ((c[w >> 2] << 1) + (c[e >> 2] | 0))) | 0;
      G = (536870904 - ((c[d >> 2] << 1) + (c[f >> 2] | 0))) | 0;
      F = (536870904 - ((c[b >> 2] << 1) + (c[g >> 2] | 0))) | 0;
      E = (536870904 - ((c[o >> 2] << 1) + (c[v >> 2] | 0))) | 0;
      D = (536870904 - ((c[n >> 2] << 1) + (c[x >> 2] | 0))) | 0;
      l = (536870904 - ((c[m >> 2] << 1) + (c[z >> 2] | 0))) | 0;
      j = (33554424 - ((c[k >> 2] << 1) + (c[h >> 2] | 0))) | 0;
      K =
        (536863096 - ((c[a >> 2] << 1) + (c[p >> 2] | 0)) + (c[r >> 2] | 0)) |
        0;
      c[a >> 2] = K;
      J = (J + (c[(r + 4) >> 2] | 0)) | 0;
      c[A >> 2] = J;
      I = (I + (c[(r + 8) >> 2] | 0)) | 0;
      c[y >> 2] = I;
      H = (H + (c[(r + 12) >> 2] | 0)) | 0;
      c[w >> 2] = H;
      G = (G + (c[(r + 16) >> 2] | 0)) | 0;
      c[d >> 2] = G;
      F = (F + (c[(r + 20) >> 2] | 0)) | 0;
      c[b >> 2] = F;
      E = (E + (c[(r + 24) >> 2] | 0)) | 0;
      c[o >> 2] = E;
      D = (D + (c[(r + 28) >> 2] | 0)) | 0;
      c[n >> 2] = D;
      l = (l + (c[(r + 32) >> 2] | 0)) | 0;
      c[m >> 2] = l;
      j = (j + (c[(r + 36) >> 2] | 0)) | 0;
      c[k >> 2] = j;
      k = (a + 40) | 0;
      m = (a + 44) | 0;
      n = (a + 48) | 0;
      o = (a + 52) | 0;
      b = (a + 56) | 0;
      d = (a + 60) | 0;
      r = (a + 64) | 0;
      w = (a + 68) | 0;
      y = (a + 72) | 0;
      A = (a + 76) | 0;
      c[k >> 2] = 805294644 - K + (c[t >> 2] | 0);
      c[m >> 2] = 805305588 - J + (c[(t + 4) >> 2] | 0);
      c[n >> 2] = 805306356 - I + (c[(t + 8) >> 2] | 0);
      c[o >> 2] = 805306356 - H + (c[(t + 12) >> 2] | 0);
      c[b >> 2] = 805306356 - G + (c[(t + 16) >> 2] | 0);
      c[d >> 2] = 805306356 - F + (c[(t + 20) >> 2] | 0);
      c[r >> 2] = 805306356 - E + (c[(t + 24) >> 2] | 0);
      c[w >> 2] = 805306356 - D + (c[(t + 28) >> 2] | 0);
      c[y >> 2] = 805306356 - l + (c[(t + 32) >> 2] | 0);
      c[A >> 2] = 50331636 - j + (c[(t + 36) >> 2] | 0);
      Va(k, k, q);
      Va(p, p, s);
      j = (268431548 - (c[p >> 2] | 0)) | 0;
      c[p >> 2] = j;
      l = (268435196 - (c[C >> 2] | 0)) | 0;
      c[C >> 2] = l;
      p = (268435452 - (c[B >> 2] | 0)) | 0;
      c[B >> 2] = p;
      q = (268435452 - (c[e >> 2] | 0)) | 0;
      c[e >> 2] = q;
      a = (268435452 - (c[f >> 2] | 0)) | 0;
      c[f >> 2] = a;
      s = (268435452 - (c[g >> 2] | 0)) | 0;
      c[g >> 2] = s;
      t = (268435452 - (c[v >> 2] | 0)) | 0;
      c[v >> 2] = t;
      v = (268435452 - (c[x >> 2] | 0)) | 0;
      c[x >> 2] = v;
      x = (268435452 - (c[z >> 2] | 0)) | 0;
      c[z >> 2] = x;
      z = (16777212 - (c[h >> 2] | 0)) | 0;
      c[h >> 2] = z;
      c[k >> 2] = (c[k >> 2] | 0) + j;
      c[m >> 2] = (c[m >> 2] | 0) + l;
      c[n >> 2] = (c[n >> 2] | 0) + p;
      c[o >> 2] = (c[o >> 2] | 0) + q;
      c[b >> 2] = (c[b >> 2] | 0) + a;
      c[d >> 2] = (c[d >> 2] | 0) + s;
      c[r >> 2] = (c[r >> 2] | 0) + t;
      c[w >> 2] = (c[w >> 2] | 0) + v;
      c[y >> 2] = (c[y >> 2] | 0) + x;
      c[A >> 2] = (c[A >> 2] | 0) + z;
      i = u;
      return;
    }
    if (!(Wa(q) | 0)) {
      c[g >> 2] = 1;
      i = u;
      return;
    } else {
      Qa(a, b);
      i = u;
      return;
    }
  }
  function Sa(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0;
    c[a >> 2] = c[b >> 2] & 67108863;
    d = (b + 4) | 0;
    c[(a + 4) >> 2] = ((c[d >> 2] << 6) & 67108800) | ((c[b >> 2] | 0) >>> 26);
    e = (b + 8) | 0;
    c[(a + 8) >> 2] = ((c[e >> 2] << 12) & 67104768) | ((c[d >> 2] | 0) >>> 20);
    d = (b + 12) | 0;
    c[(a + 12) >> 2] =
      ((c[d >> 2] << 18) & 66846720) | ((c[e >> 2] | 0) >>> 14);
    e = (b + 16) | 0;
    c[(a + 16) >> 2] = ((c[e >> 2] << 24) & 50331648) | ((c[d >> 2] | 0) >>> 8);
    c[(a + 20) >> 2] = ((c[e >> 2] | 0) >>> 2) & 67108863;
    d = (b + 20) | 0;
    c[(a + 24) >> 2] = ((c[d >> 2] << 4) & 67108848) | ((c[e >> 2] | 0) >>> 28);
    e = (b + 24) | 0;
    c[(a + 28) >> 2] =
      ((c[e >> 2] << 10) & 67107840) | ((c[d >> 2] | 0) >>> 22);
    d = (b + 28) | 0;
    c[(a + 32) >> 2] =
      ((c[d >> 2] << 16) & 67043328) | ((c[e >> 2] | 0) >>> 16);
    c[(a + 36) >> 2] = (c[d >> 2] | 0) >>> 10;
    d = (b + 32) | 0;
    c[(a + 40) >> 2] = c[d >> 2] & 67108863;
    e = (b + 36) | 0;
    c[(a + 44) >> 2] = ((c[e >> 2] << 6) & 67108800) | ((c[d >> 2] | 0) >>> 26);
    d = (b + 40) | 0;
    c[(a + 48) >> 2] =
      ((c[d >> 2] << 12) & 67104768) | ((c[e >> 2] | 0) >>> 20);
    e = (b + 44) | 0;
    c[(a + 52) >> 2] =
      ((c[e >> 2] << 18) & 66846720) | ((c[d >> 2] | 0) >>> 14);
    d = (b + 48) | 0;
    c[(a + 56) >> 2] = ((c[d >> 2] << 24) & 50331648) | ((c[e >> 2] | 0) >>> 8);
    c[(a + 60) >> 2] = ((c[d >> 2] | 0) >>> 2) & 67108863;
    e = (b + 52) | 0;
    c[(a + 64) >> 2] = ((c[e >> 2] << 4) & 67108848) | ((c[d >> 2] | 0) >>> 28);
    d = (b + 56) | 0;
    c[(a + 68) >> 2] =
      ((c[d >> 2] << 10) & 67107840) | ((c[e >> 2] | 0) >>> 22);
    b = (b + 60) | 0;
    c[(a + 72) >> 2] =
      ((c[b >> 2] << 16) & 67043328) | ((c[d >> 2] | 0) >>> 16);
    c[(a + 76) >> 2] = (c[b >> 2] | 0) >>> 10;
    c[(a + 80) >> 2] = 0;
    return;
  }
  function Ta(a, b, d) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0,
      N = 0,
      O = 0,
      P = 0,
      Q = 0,
      R = 0,
      S = 0,
      T = 0,
      U = 0,
      V = 0,
      W = 0;
    F = i;
    i = (i + 448) | 0;
    t = (F + 360) | 0;
    E = (F + 160) | 0;
    s = F;
    C = (F + 280) | 0;
    r = (F + 320) | 0;
    x = (F + 400) | 0;
    A = (F + 120) | 0;
    B = (F + 240) | 0;
    y = (F + 200) | 0;
    z = (F + 80) | 0;
    D = (F + 40) | 0;
    e = c[(d + 80) >> 2] | 0;
    if (c[(b + 120) >> 2] | 0) {
      c[(a + 120) >> 2] = e;
      u = (a + 0) | 0;
      v = (d + 0) | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      u = (a + 40) | 0;
      v = (d + 40) | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      c[(a + 80) >> 2] = 1;
      u = (a + 84) | 0;
      w = (u + 36) | 0;
      do {
        c[u >> 2] = 0;
        u = (u + 4) | 0;
      } while ((u | 0) < (w | 0));
      i = F;
      return;
    }
    if (e) {
      u = (a + 0) | 0;
      v = (b + 0) | 0;
      w = (u + 124) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      i = F;
      return;
    }
    e = (a + 120) | 0;
    c[e >> 2] = 0;
    q = (b + 80) | 0;
    Ua(t, q);
    u = (E + 0) | 0;
    v = (b + 0) | 0;
    w = (u + 40) | 0;
    do {
      c[u >> 2] = c[v >> 2];
      u = (u + 4) | 0;
      v = (v + 4) | 0;
    } while ((u | 0) < (w | 0));
    L = (E + 4) | 0;
    K = (E + 8) | 0;
    J = (E + 12) | 0;
    I = (E + 16) | 0;
    H = (E + 20) | 0;
    G = (E + 24) | 0;
    w = (E + 28) | 0;
    v = (E + 32) | 0;
    u = (E + 36) | 0;
    o = c[u >> 2] | 0;
    g = o >>> 22;
    f = (((g * 977) | 0) + (c[E >> 2] | 0)) | 0;
    g = ((g << 6) + (c[L >> 2] | 0) + (f >>> 26)) | 0;
    f = f & 67108863;
    h = ((g >>> 26) + (c[K >> 2] | 0)) | 0;
    g = g & 67108863;
    j = ((h >>> 26) + (c[J >> 2] | 0)) | 0;
    h = h & 67108863;
    k = ((j >>> 26) + (c[I >> 2] | 0)) | 0;
    j = j & 67108863;
    l = ((k >>> 26) + (c[H >> 2] | 0)) | 0;
    k = k & 67108863;
    m = ((l >>> 26) + (c[G >> 2] | 0)) | 0;
    l = l & 67108863;
    n = ((m >>> 26) + (c[w >> 2] | 0)) | 0;
    m = m & 67108863;
    p = ((n >>> 26) + (c[v >> 2] | 0)) | 0;
    n = n & 67108863;
    o = ((p >>> 26) + (o & 4194303)) | 0;
    p = p & 67108863;
    c[E >> 2] = f;
    c[L >> 2] = g;
    c[K >> 2] = h;
    c[J >> 2] = j;
    c[I >> 2] = k;
    c[H >> 2] = l;
    c[G >> 2] = m;
    c[w >> 2] = n;
    c[v >> 2] = p;
    c[u >> 2] = o;
    Va(s, d, t);
    u = (C + 0) | 0;
    v = (b + 40) | 0;
    w = (u + 40) | 0;
    do {
      c[u >> 2] = c[v >> 2];
      u = (u + 4) | 0;
      v = (v + 4) | 0;
    } while ((u | 0) < (w | 0));
    W = (C + 4) | 0;
    V = (C + 8) | 0;
    U = (C + 12) | 0;
    T = (C + 16) | 0;
    S = (C + 20) | 0;
    R = (C + 24) | 0;
    Q = (C + 28) | 0;
    P = (C + 32) | 0;
    L = (C + 36) | 0;
    N = c[L >> 2] | 0;
    u = N >>> 22;
    M = (((u * 977) | 0) + (c[C >> 2] | 0)) | 0;
    u = ((u << 6) + (c[W >> 2] | 0) + (M >>> 26)) | 0;
    M = M & 67108863;
    v = ((u >>> 26) + (c[V >> 2] | 0)) | 0;
    u = u & 67108863;
    w = ((v >>> 26) + (c[U >> 2] | 0)) | 0;
    v = v & 67108863;
    G = ((w >>> 26) + (c[T >> 2] | 0)) | 0;
    w = w & 67108863;
    H = ((G >>> 26) + (c[S >> 2] | 0)) | 0;
    G = G & 67108863;
    I = ((H >>> 26) + (c[R >> 2] | 0)) | 0;
    H = H & 67108863;
    J = ((I >>> 26) + (c[Q >> 2] | 0)) | 0;
    I = I & 67108863;
    O = ((J >>> 26) + (c[P >> 2] | 0)) | 0;
    J = J & 67108863;
    K = O & 67108863;
    c[C >> 2] = M;
    c[W >> 2] = u;
    c[V >> 2] = v;
    c[U >> 2] = w;
    c[T >> 2] = G;
    c[S >> 2] = H;
    c[R >> 2] = I;
    c[Q >> 2] = J;
    c[P >> 2] = K;
    c[L >> 2] = (O >>> 26) + (N & 4194303);
    Va(r, (d + 40) | 0, t);
    Va(r, r, q);
    c[x >> 2] = 268431548 - f + (c[s >> 2] | 0);
    c[(x + 4) >> 2] = 268435196 - g + (c[(s + 4) >> 2] | 0);
    c[(x + 8) >> 2] = 268435452 - h + (c[(s + 8) >> 2] | 0);
    c[(x + 12) >> 2] = 268435452 - j + (c[(s + 12) >> 2] | 0);
    c[(x + 16) >> 2] = 268435452 - k + (c[(s + 16) >> 2] | 0);
    c[(x + 20) >> 2] = 268435452 - l + (c[(s + 20) >> 2] | 0);
    c[(x + 24) >> 2] = 268435452 - m + (c[(s + 24) >> 2] | 0);
    c[(x + 28) >> 2] = 268435452 - n + (c[(s + 28) >> 2] | 0);
    c[(x + 32) >> 2] = 268435452 - p + (c[(s + 32) >> 2] | 0);
    c[(x + 36) >> 2] = 16777212 - o + (c[(s + 36) >> 2] | 0);
    L = (16777212 - (c[L >> 2] | 0)) | 0;
    c[A >> 2] = 268431548 - M + (c[r >> 2] | 0);
    c[(A + 4) >> 2] = 268435196 - u + (c[(r + 4) >> 2] | 0);
    c[(A + 8) >> 2] = 268435452 - v + (c[(r + 8) >> 2] | 0);
    c[(A + 12) >> 2] = 268435452 - w + (c[(r + 12) >> 2] | 0);
    c[(A + 16) >> 2] = 268435452 - G + (c[(r + 16) >> 2] | 0);
    c[(A + 20) >> 2] = 268435452 - H + (c[(r + 20) >> 2] | 0);
    c[(A + 24) >> 2] = 268435452 - I + (c[(r + 24) >> 2] | 0);
    c[(A + 28) >> 2] = 268435452 - J + (c[(r + 28) >> 2] | 0);
    c[(A + 32) >> 2] = 268435452 - K + (c[(r + 32) >> 2] | 0);
    c[(A + 36) >> 2] = L + (c[(r + 36) >> 2] | 0);
    if (!(Wa(x) | 0)) {
      Ua(B, A);
      Ua(y, x);
      Va(z, x, y);
      e = (a + 80) | 0;
      u = (e + 0) | 0;
      v = (q + 0) | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      Va(e, e, x);
      Va(D, E, y);
      u = (a + 0) | 0;
      v = (D + 0) | 0;
      w = (u + 40) | 0;
      do {
        c[u >> 2] = c[v >> 2];
        u = (u + 4) | 0;
        v = (v + 4) | 0;
      } while ((u | 0) < (w | 0));
      W = (a + 4) | 0;
      U = (a + 8) | 0;
      S = (a + 12) | 0;
      Q = (a + 16) | 0;
      O = (a + 20) | 0;
      M = (a + 24) | 0;
      K = (a + 28) | 0;
      I = (a + 32) | 0;
      G = (a + 36) | 0;
      H = (z + 4) | 0;
      J = (z + 8) | 0;
      L = (z + 12) | 0;
      N = (z + 16) | 0;
      P = (z + 20) | 0;
      R = (z + 24) | 0;
      T = (z + 28) | 0;
      V = (z + 32) | 0;
      y = (z + 36) | 0;
      d = (536870392 - ((c[W >> 2] << 1) + (c[H >> 2] | 0))) | 0;
      r = (536870904 - ((c[U >> 2] << 1) + (c[J >> 2] | 0))) | 0;
      s = (536870904 - ((c[S >> 2] << 1) + (c[L >> 2] | 0))) | 0;
      t = (536870904 - ((c[Q >> 2] << 1) + (c[N >> 2] | 0))) | 0;
      u = (536870904 - ((c[O >> 2] << 1) + (c[P >> 2] | 0))) | 0;
      v = (536870904 - ((c[M >> 2] << 1) + (c[R >> 2] | 0))) | 0;
      w = (536870904 - ((c[K >> 2] << 1) + (c[T >> 2] | 0))) | 0;
      x = (536870904 - ((c[I >> 2] << 1) + (c[V >> 2] | 0))) | 0;
      E = (33554424 - ((c[G >> 2] << 1) + (c[y >> 2] | 0))) | 0;
      b =
        (536863096 - ((c[a >> 2] << 1) + (c[z >> 2] | 0)) + (c[B >> 2] | 0)) |
        0;
      c[a >> 2] = b;
      d = (d + (c[(B + 4) >> 2] | 0)) | 0;
      c[W >> 2] = d;
      r = (r + (c[(B + 8) >> 2] | 0)) | 0;
      c[U >> 2] = r;
      s = (s + (c[(B + 12) >> 2] | 0)) | 0;
      c[S >> 2] = s;
      t = (t + (c[(B + 16) >> 2] | 0)) | 0;
      c[Q >> 2] = t;
      u = (u + (c[(B + 20) >> 2] | 0)) | 0;
      c[O >> 2] = u;
      v = (v + (c[(B + 24) >> 2] | 0)) | 0;
      c[M >> 2] = v;
      w = (w + (c[(B + 28) >> 2] | 0)) | 0;
      c[K >> 2] = w;
      x = (x + (c[(B + 32) >> 2] | 0)) | 0;
      c[I >> 2] = x;
      E = (E + (c[(B + 36) >> 2] | 0)) | 0;
      c[G >> 2] = E;
      B = (a + 40) | 0;
      G = (a + 44) | 0;
      I = (a + 48) | 0;
      K = (a + 52) | 0;
      M = (a + 56) | 0;
      O = (a + 60) | 0;
      Q = (a + 64) | 0;
      S = (a + 68) | 0;
      U = (a + 72) | 0;
      W = (a + 76) | 0;
      c[B >> 2] = 805294644 - b + (c[D >> 2] | 0);
      c[G >> 2] = 805305588 - d + (c[(D + 4) >> 2] | 0);
      c[I >> 2] = 805306356 - r + (c[(D + 8) >> 2] | 0);
      c[K >> 2] = 805306356 - s + (c[(D + 12) >> 2] | 0);
      c[M >> 2] = 805306356 - t + (c[(D + 16) >> 2] | 0);
      c[O >> 2] = 805306356 - u + (c[(D + 20) >> 2] | 0);
      c[Q >> 2] = 805306356 - v + (c[(D + 24) >> 2] | 0);
      c[S >> 2] = 805306356 - w + (c[(D + 28) >> 2] | 0);
      c[U >> 2] = 805306356 - x + (c[(D + 32) >> 2] | 0);
      c[W >> 2] = 50331636 - E + (c[(D + 36) >> 2] | 0);
      Va(B, B, A);
      Va(z, z, C);
      D = (268431548 - (c[z >> 2] | 0)) | 0;
      c[z >> 2] = D;
      E = (268435196 - (c[H >> 2] | 0)) | 0;
      c[H >> 2] = E;
      H = (268435452 - (c[J >> 2] | 0)) | 0;
      c[J >> 2] = H;
      J = (268435452 - (c[L >> 2] | 0)) | 0;
      c[L >> 2] = J;
      L = (268435452 - (c[N >> 2] | 0)) | 0;
      c[N >> 2] = L;
      N = (268435452 - (c[P >> 2] | 0)) | 0;
      c[P >> 2] = N;
      P = (268435452 - (c[R >> 2] | 0)) | 0;
      c[R >> 2] = P;
      R = (268435452 - (c[T >> 2] | 0)) | 0;
      c[T >> 2] = R;
      T = (268435452 - (c[V >> 2] | 0)) | 0;
      c[V >> 2] = T;
      V = (16777212 - (c[y >> 2] | 0)) | 0;
      c[y >> 2] = V;
      c[B >> 2] = (c[B >> 2] | 0) + D;
      c[G >> 2] = (c[G >> 2] | 0) + E;
      c[I >> 2] = (c[I >> 2] | 0) + H;
      c[K >> 2] = (c[K >> 2] | 0) + J;
      c[M >> 2] = (c[M >> 2] | 0) + L;
      c[O >> 2] = (c[O >> 2] | 0) + N;
      c[Q >> 2] = (c[Q >> 2] | 0) + P;
      c[S >> 2] = (c[S >> 2] | 0) + R;
      c[U >> 2] = (c[U >> 2] | 0) + T;
      c[W >> 2] = (c[W >> 2] | 0) + V;
      i = F;
      return;
    }
    if (!(Wa(A) | 0)) {
      c[e >> 2] = 1;
      i = F;
      return;
    } else {
      Qa(a, b);
      i = F;
      return;
    }
  }
  function Ua(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0,
      N = 0;
    d = i;
    k = c[b >> 2] | 0;
    B = k << 1;
    m = c[(b + 36) >> 2] | 0;
    M = Bb(B | 0, 0, m | 0, 0) | 0;
    v = E;
    I = c[(b + 4) >> 2] | 0;
    t = I << 1;
    z = c[(b + 32) >> 2] | 0;
    J = Bb(t | 0, 0, z | 0, 0) | 0;
    v = ob(J | 0, E | 0, M | 0, v | 0) | 0;
    M = E;
    J = c[(b + 8) >> 2] | 0;
    C = J << 1;
    D = c[(b + 28) >> 2] | 0;
    A = Bb(C | 0, 0, D | 0, 0) | 0;
    A = ob(v | 0, M | 0, A | 0, E | 0) | 0;
    M = E;
    v = c[(b + 12) >> 2] | 0;
    y = v << 1;
    u = c[(b + 24) >> 2] | 0;
    n = Bb(y | 0, 0, u | 0, 0) | 0;
    n = ob(A | 0, M | 0, n | 0, E | 0) | 0;
    M = E;
    A = c[(b + 16) >> 2] | 0;
    G = A << 1;
    x = c[(b + 20) >> 2] | 0;
    o = Bb(G | 0, 0, x | 0, 0) | 0;
    o = ob(n | 0, M | 0, o | 0, E | 0) | 0;
    M = qb(o | 0, E | 0, 26) | 0;
    n = E;
    k = Bb(k | 0, 0, k | 0, 0) | 0;
    l = E;
    K = Bb(t | 0, 0, m | 0, 0) | 0;
    b = E;
    F = Bb(C | 0, 0, z | 0, 0) | 0;
    b = ob(F | 0, E | 0, K | 0, b | 0) | 0;
    K = E;
    F = Bb(y | 0, 0, D | 0, 0) | 0;
    F = ob(b | 0, K | 0, F | 0, E | 0) | 0;
    K = E;
    b = Bb(G | 0, 0, u | 0, 0) | 0;
    b = ob(F | 0, K | 0, b | 0, E | 0) | 0;
    K = E;
    F = Bb(x | 0, 0, x | 0, 0) | 0;
    F = ob(b | 0, K | 0, F | 0, E | 0) | 0;
    n = ob(F | 0, E | 0, M | 0, n | 0) | 0;
    M = n & 67108863;
    n = qb(n | 0, E | 0, 26) | 0;
    F = E;
    K = Bb(M | 0, 0, 15632, 0) | 0;
    l = ob(K | 0, E | 0, k | 0, l | 0) | 0;
    k = E;
    K = qb(l | 0, k | 0, 26) | 0;
    b = E;
    M = rb(M | 0, 0, 10) | 0;
    p = E;
    L = Bb(I | 0, 0, B | 0, 0) | 0;
    e = E;
    s = Bb(C | 0, 0, m | 0, 0) | 0;
    N = E;
    g = Bb(y | 0, 0, z | 0, 0) | 0;
    N = ob(g | 0, E | 0, s | 0, N | 0) | 0;
    s = E;
    g = Bb(G | 0, 0, D | 0, 0) | 0;
    g = ob(N | 0, s | 0, g | 0, E | 0) | 0;
    s = E;
    N = x << 1;
    H = Bb(N | 0, 0, u | 0, 0) | 0;
    H = ob(g | 0, s | 0, H | 0, E | 0) | 0;
    F = ob(H | 0, E | 0, n | 0, F | 0) | 0;
    n = F & 67108863;
    F = qb(F | 0, E | 0, 26) | 0;
    H = E;
    s = Bb(n | 0, 0, 15632, 0) | 0;
    g = E;
    e = ob(M | 0, p | 0, L | 0, e | 0) | 0;
    b = ob(e | 0, E | 0, K | 0, b | 0) | 0;
    g = ob(b | 0, E | 0, s | 0, g | 0) | 0;
    s = qb(g | 0, E | 0, 26) | 0;
    b = E;
    n = rb(n | 0, 0, 10) | 0;
    K = E;
    e = Bb(J | 0, 0, B | 0, 0) | 0;
    L = E;
    I = Bb(I | 0, 0, I | 0, 0) | 0;
    I = ob(e | 0, L | 0, I | 0, E | 0) | 0;
    L = E;
    e = Bb(y | 0, 0, m | 0, 0) | 0;
    p = E;
    M = Bb(G | 0, 0, z | 0, 0) | 0;
    r = E;
    j = Bb(N | 0, 0, D | 0, 0) | 0;
    h = E;
    w = Bb(u | 0, 0, u | 0, 0) | 0;
    p = ob(w | 0, E | 0, e | 0, p | 0) | 0;
    r = ob(p | 0, E | 0, M | 0, r | 0) | 0;
    h = ob(r | 0, E | 0, j | 0, h | 0) | 0;
    H = ob(h | 0, E | 0, F | 0, H | 0) | 0;
    F = H & 67108863;
    H = qb(H | 0, E | 0, 26) | 0;
    h = E;
    j = Bb(F | 0, 0, 15632, 0) | 0;
    r = E;
    K = ob(I | 0, L | 0, n | 0, K | 0) | 0;
    r = ob(K | 0, E | 0, j | 0, r | 0) | 0;
    b = ob(r | 0, E | 0, s | 0, b | 0) | 0;
    s = qb(b | 0, E | 0, 26) | 0;
    r = E;
    F = rb(F | 0, 0, 10) | 0;
    j = E;
    K = Bb(v | 0, 0, B | 0, 0) | 0;
    n = E;
    L = Bb(J | 0, 0, t | 0, 0) | 0;
    L = ob(K | 0, n | 0, L | 0, E | 0) | 0;
    n = E;
    G = Bb(G | 0, 0, m | 0, 0) | 0;
    K = E;
    I = Bb(N | 0, 0, z | 0, 0) | 0;
    M = E;
    p = u << 1;
    e = Bb(p | 0, 0, D | 0, 0) | 0;
    e = ob(G | 0, K | 0, e | 0, E | 0) | 0;
    M = ob(e | 0, E | 0, I | 0, M | 0) | 0;
    h = ob(M | 0, E | 0, H | 0, h | 0) | 0;
    H = h & 67108863;
    h = qb(h | 0, E | 0, 26) | 0;
    M = E;
    I = Bb(H | 0, 0, 15632, 0) | 0;
    e = E;
    j = ob(L | 0, n | 0, F | 0, j | 0) | 0;
    e = ob(j | 0, E | 0, I | 0, e | 0) | 0;
    r = ob(e | 0, E | 0, s | 0, r | 0) | 0;
    s = qb(r | 0, E | 0, 26) | 0;
    e = E;
    H = rb(H | 0, 0, 10) | 0;
    I = E;
    j = Bb(A | 0, 0, B | 0, 0) | 0;
    F = E;
    n = Bb(v | 0, 0, t | 0, 0) | 0;
    L = E;
    J = Bb(J | 0, 0, J | 0, 0) | 0;
    K = E;
    N = Bb(N | 0, 0, m | 0, 0) | 0;
    G = E;
    w = Bb(p | 0, 0, z | 0, 0) | 0;
    q = E;
    f = Bb(D | 0, 0, D | 0, 0) | 0;
    f = ob(w | 0, q | 0, f | 0, E | 0) | 0;
    G = ob(f | 0, E | 0, N | 0, G | 0) | 0;
    M = ob(G | 0, E | 0, h | 0, M | 0) | 0;
    h = M & 67108863;
    M = qb(M | 0, E | 0, 26) | 0;
    G = E;
    N = Bb(h | 0, 0, 15632, 0) | 0;
    f = E;
    K = ob(n | 0, L | 0, J | 0, K | 0) | 0;
    F = ob(K | 0, E | 0, j | 0, F | 0) | 0;
    I = ob(F | 0, E | 0, H | 0, I | 0) | 0;
    f = ob(I | 0, E | 0, N | 0, f | 0) | 0;
    e = ob(f | 0, E | 0, s | 0, e | 0) | 0;
    s = qb(e | 0, E | 0, 26) | 0;
    f = E;
    h = rb(h | 0, 0, 10) | 0;
    N = E;
    I = Bb(x | 0, 0, B | 0, 0) | 0;
    H = E;
    F = Bb(A | 0, 0, t | 0, 0) | 0;
    j = E;
    K = Bb(v | 0, 0, C | 0, 0) | 0;
    J = E;
    p = Bb(p | 0, 0, m | 0, 0) | 0;
    L = E;
    n = D << 1;
    q = Bb(n | 0, 0, z | 0, 0) | 0;
    q = ob(p | 0, L | 0, q | 0, E | 0) | 0;
    G = ob(q | 0, E | 0, M | 0, G | 0) | 0;
    M = G & 67108863;
    G = qb(G | 0, E | 0, 26) | 0;
    q = E;
    L = Bb(M | 0, 0, 15632, 0) | 0;
    p = E;
    J = ob(F | 0, j | 0, K | 0, J | 0) | 0;
    H = ob(J | 0, E | 0, I | 0, H | 0) | 0;
    N = ob(H | 0, E | 0, h | 0, N | 0) | 0;
    p = ob(N | 0, E | 0, L | 0, p | 0) | 0;
    f = ob(p | 0, E | 0, s | 0, f | 0) | 0;
    s = qb(f | 0, E | 0, 26) | 0;
    p = E;
    M = rb(M | 0, 0, 10) | 0;
    L = E;
    N = Bb(u | 0, 0, B | 0, 0) | 0;
    h = E;
    H = Bb(x | 0, 0, t | 0, 0) | 0;
    I = E;
    J = Bb(A | 0, 0, C | 0, 0) | 0;
    K = E;
    v = Bb(v | 0, 0, v | 0, 0) | 0;
    j = E;
    n = Bb(n | 0, 0, m | 0, 0) | 0;
    F = E;
    w = Bb(z | 0, 0, z | 0, 0) | 0;
    w = ob(n | 0, F | 0, w | 0, E | 0) | 0;
    q = ob(w | 0, E | 0, G | 0, q | 0) | 0;
    G = q & 67108863;
    q = qb(q | 0, E | 0, 26) | 0;
    w = E;
    F = Bb(G | 0, 0, 15632, 0) | 0;
    n = E;
    j = ob(N | 0, h | 0, v | 0, j | 0) | 0;
    K = ob(j | 0, E | 0, J | 0, K | 0) | 0;
    I = ob(K | 0, E | 0, H | 0, I | 0) | 0;
    L = ob(I | 0, E | 0, M | 0, L | 0) | 0;
    n = ob(L | 0, E | 0, F | 0, n | 0) | 0;
    p = ob(n | 0, E | 0, s | 0, p | 0) | 0;
    s = qb(p | 0, E | 0, 26) | 0;
    n = E;
    G = rb(G | 0, 0, 10) | 0;
    F = E;
    L = Bb(D | 0, 0, B | 0, 0) | 0;
    M = E;
    I = Bb(u | 0, 0, t | 0, 0) | 0;
    M = ob(I | 0, E | 0, L | 0, M | 0) | 0;
    L = E;
    I = Bb(x | 0, 0, C | 0, 0) | 0;
    H = E;
    K = Bb(A | 0, 0, y | 0, 0) | 0;
    J = E;
    j = Bb((z << 1) | 0, 0, m | 0, 0) | 0;
    j = ob(q | 0, w | 0, j | 0, E | 0) | 0;
    w = j & 67108863;
    j = qb(j | 0, E | 0, 26) | 0;
    q = E;
    v = Bb(w | 0, 0, 15632, 0) | 0;
    h = E;
    J = ob(M | 0, L | 0, K | 0, J | 0) | 0;
    H = ob(J | 0, E | 0, I | 0, H | 0) | 0;
    F = ob(H | 0, E | 0, G | 0, F | 0) | 0;
    h = ob(F | 0, E | 0, v | 0, h | 0) | 0;
    n = ob(h | 0, E | 0, s | 0, n | 0) | 0;
    s = qb(n | 0, E | 0, 26) | 0;
    h = E;
    w = rb(w | 0, 0, 10) | 0;
    v = E;
    B = Bb(z | 0, 0, B | 0, 0) | 0;
    z = E;
    t = Bb(D | 0, 0, t | 0, 0) | 0;
    z = ob(t | 0, E | 0, B | 0, z | 0) | 0;
    B = E;
    C = Bb(u | 0, 0, C | 0, 0) | 0;
    C = ob(z | 0, B | 0, C | 0, E | 0) | 0;
    B = E;
    y = Bb(x | 0, 0, y | 0, 0) | 0;
    x = E;
    A = Bb(A | 0, 0, A | 0, 0) | 0;
    z = E;
    m = Bb(m | 0, 0, m | 0, 0) | 0;
    m = ob(j | 0, q | 0, m | 0, E | 0) | 0;
    q = m & 67108863;
    m = qb(m | 0, E | 0, 26) | 0;
    j = E;
    u = Bb(q | 0, 0, 15632, 0) | 0;
    t = E;
    z = ob(C | 0, B | 0, A | 0, z | 0) | 0;
    x = ob(z | 0, E | 0, y | 0, x | 0) | 0;
    v = ob(x | 0, E | 0, w | 0, v | 0) | 0;
    t = ob(v | 0, E | 0, u | 0, t | 0) | 0;
    h = ob(t | 0, E | 0, s | 0, h | 0) | 0;
    c[(a + 12) >> 2] = r & 67108863;
    c[(a + 16) >> 2] = e & 67108863;
    c[(a + 20) >> 2] = f & 67108863;
    c[(a + 24) >> 2] = p & 67108863;
    c[(a + 28) >> 2] = n & 67108863;
    c[(a + 32) >> 2] = h & 67108863;
    h = qb(h | 0, E | 0, 26) | 0;
    n = E;
    q = rb(q | 0, 0, 10) | 0;
    p = E;
    f = Bb(m | 0, j | 0, 15632, 0) | 0;
    e = E;
    o = ob(q | 0, p | 0, (o & 67108863) | 0, 0) | 0;
    e = ob(o | 0, E | 0, f | 0, e | 0) | 0;
    n = ob(e | 0, E | 0, h | 0, n | 0) | 0;
    c[(a + 36) >> 2] = n & 4194303;
    n = qb(n | 0, E | 0, 22) | 0;
    h = E;
    j = rb(m | 0, j | 0, 14) | 0;
    j = ob(n | 0, h | 0, j | 0, E | 0) | 0;
    h = E;
    n = Bb(j | 0, h | 0, 977, 0) | 0;
    m = E;
    e = ob(n | 0, m | 0, (l & 67108863) | 0, 0) | 0;
    f = E;
    k = ob(n | 0, m | 0, l | 0, k | 0) | 0;
    c[a >> 2] = k & 67108863;
    f = qb(e | 0, f | 0, 26) | 0;
    e = E;
    h = rb(j | 0, h | 0, 6) | 0;
    g = ob(h | 0, E | 0, (g & 67108863) | 0, 0) | 0;
    e = ob(g | 0, E | 0, f | 0, e | 0) | 0;
    c[(a + 4) >> 2] = e & 67108863;
    e = qb(e | 0, E | 0, 26) | 0;
    b = ob(e | 0, E | 0, (b & 67108863) | 0, 0) | 0;
    c[(a + 8) >> 2] = b;
    i = d;
    return;
  }
  function Va(a, b, d) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0,
      N = 0,
      O = 0,
      P = 0,
      Q = 0,
      R = 0,
      S = 0;
    e = i;
    x = c[b >> 2] | 0;
    m = c[(d + 36) >> 2] | 0;
    R = Bb(m | 0, 0, x | 0, 0) | 0;
    H = E;
    N = c[(b + 4) >> 2] | 0;
    L = c[(d + 32) >> 2] | 0;
    J = Bb(L | 0, 0, N | 0, 0) | 0;
    H = ob(J | 0, E | 0, R | 0, H | 0) | 0;
    R = E;
    J = c[(b + 8) >> 2] | 0;
    O = c[(d + 28) >> 2] | 0;
    F = Bb(O | 0, 0, J | 0, 0) | 0;
    F = ob(H | 0, R | 0, F | 0, E | 0) | 0;
    R = E;
    H = c[(b + 12) >> 2] | 0;
    M = c[(d + 24) >> 2] | 0;
    C = Bb(M | 0, 0, H | 0, 0) | 0;
    C = ob(F | 0, R | 0, C | 0, E | 0) | 0;
    R = E;
    F = c[(b + 16) >> 2] | 0;
    K = c[(d + 20) >> 2] | 0;
    A = Bb(K | 0, 0, F | 0, 0) | 0;
    A = ob(C | 0, R | 0, A | 0, E | 0) | 0;
    R = E;
    C = c[(b + 20) >> 2] | 0;
    I = c[(d + 16) >> 2] | 0;
    t = Bb(I | 0, 0, C | 0, 0) | 0;
    t = ob(A | 0, R | 0, t | 0, E | 0) | 0;
    R = E;
    A = c[(b + 24) >> 2] | 0;
    G = c[(d + 12) >> 2] | 0;
    y = Bb(G | 0, 0, A | 0, 0) | 0;
    y = ob(t | 0, R | 0, y | 0, E | 0) | 0;
    R = E;
    t = c[(b + 28) >> 2] | 0;
    D = c[(d + 8) >> 2] | 0;
    u = Bb(D | 0, 0, t | 0, 0) | 0;
    u = ob(y | 0, R | 0, u | 0, E | 0) | 0;
    R = E;
    y = c[(b + 32) >> 2] | 0;
    B = c[(d + 4) >> 2] | 0;
    f = Bb(B | 0, 0, y | 0, 0) | 0;
    f = ob(u | 0, R | 0, f | 0, E | 0) | 0;
    R = E;
    u = c[(b + 36) >> 2] | 0;
    z = c[d >> 2] | 0;
    o = Bb(z | 0, 0, u | 0, 0) | 0;
    o = ob(f | 0, R | 0, o | 0, E | 0) | 0;
    R = qb(o | 0, E | 0, 26) | 0;
    f = E;
    k = Bb(z | 0, 0, x | 0, 0) | 0;
    l = E;
    w = Bb(N | 0, 0, m | 0, 0) | 0;
    d = E;
    v = Bb(J | 0, 0, L | 0, 0) | 0;
    d = ob(v | 0, E | 0, w | 0, d | 0) | 0;
    w = E;
    v = Bb(H | 0, 0, O | 0, 0) | 0;
    v = ob(d | 0, w | 0, v | 0, E | 0) | 0;
    w = E;
    d = Bb(F | 0, 0, M | 0, 0) | 0;
    d = ob(v | 0, w | 0, d | 0, E | 0) | 0;
    w = E;
    v = Bb(C | 0, 0, K | 0, 0) | 0;
    v = ob(d | 0, w | 0, v | 0, E | 0) | 0;
    w = E;
    d = Bb(A | 0, 0, I | 0, 0) | 0;
    d = ob(v | 0, w | 0, d | 0, E | 0) | 0;
    w = E;
    v = Bb(t | 0, 0, G | 0, 0) | 0;
    v = ob(d | 0, w | 0, v | 0, E | 0) | 0;
    w = E;
    d = Bb(y | 0, 0, D | 0, 0) | 0;
    d = ob(v | 0, w | 0, d | 0, E | 0) | 0;
    w = E;
    v = Bb(u | 0, 0, B | 0, 0) | 0;
    v = ob(d | 0, w | 0, v | 0, E | 0) | 0;
    f = ob(v | 0, E | 0, R | 0, f | 0) | 0;
    R = f & 67108863;
    f = qb(f | 0, E | 0, 26) | 0;
    v = E;
    w = Bb(R | 0, 0, 15632, 0) | 0;
    l = ob(w | 0, E | 0, k | 0, l | 0) | 0;
    k = E;
    w = qb(l | 0, k | 0, 26) | 0;
    d = E;
    R = rb(R | 0, 0, 10) | 0;
    q = E;
    S = Bb(B | 0, 0, x | 0, 0) | 0;
    r = E;
    s = Bb(z | 0, 0, N | 0, 0) | 0;
    r = ob(s | 0, E | 0, S | 0, r | 0) | 0;
    S = E;
    s = Bb(J | 0, 0, m | 0, 0) | 0;
    n = E;
    g = Bb(H | 0, 0, L | 0, 0) | 0;
    n = ob(g | 0, E | 0, s | 0, n | 0) | 0;
    s = E;
    g = Bb(F | 0, 0, O | 0, 0) | 0;
    g = ob(n | 0, s | 0, g | 0, E | 0) | 0;
    s = E;
    n = Bb(C | 0, 0, M | 0, 0) | 0;
    n = ob(g | 0, s | 0, n | 0, E | 0) | 0;
    s = E;
    g = Bb(A | 0, 0, K | 0, 0) | 0;
    g = ob(n | 0, s | 0, g | 0, E | 0) | 0;
    s = E;
    n = Bb(t | 0, 0, I | 0, 0) | 0;
    n = ob(g | 0, s | 0, n | 0, E | 0) | 0;
    s = E;
    g = Bb(y | 0, 0, G | 0, 0) | 0;
    g = ob(n | 0, s | 0, g | 0, E | 0) | 0;
    s = E;
    n = Bb(u | 0, 0, D | 0, 0) | 0;
    n = ob(g | 0, s | 0, n | 0, E | 0) | 0;
    v = ob(n | 0, E | 0, f | 0, v | 0) | 0;
    f = v & 67108863;
    v = qb(v | 0, E | 0, 26) | 0;
    n = E;
    s = Bb(f | 0, 0, 15632, 0) | 0;
    g = E;
    q = ob(r | 0, S | 0, R | 0, q | 0) | 0;
    d = ob(q | 0, E | 0, w | 0, d | 0) | 0;
    g = ob(d | 0, E | 0, s | 0, g | 0) | 0;
    s = qb(g | 0, E | 0, 26) | 0;
    d = E;
    f = rb(f | 0, 0, 10) | 0;
    w = E;
    q = Bb(D | 0, 0, x | 0, 0) | 0;
    R = E;
    S = Bb(B | 0, 0, N | 0, 0) | 0;
    R = ob(S | 0, E | 0, q | 0, R | 0) | 0;
    q = E;
    S = Bb(z | 0, 0, J | 0, 0) | 0;
    S = ob(R | 0, q | 0, S | 0, E | 0) | 0;
    q = E;
    R = Bb(H | 0, 0, m | 0, 0) | 0;
    r = E;
    P = Bb(F | 0, 0, L | 0, 0) | 0;
    r = ob(P | 0, E | 0, R | 0, r | 0) | 0;
    R = E;
    P = Bb(C | 0, 0, O | 0, 0) | 0;
    P = ob(r | 0, R | 0, P | 0, E | 0) | 0;
    R = E;
    r = Bb(A | 0, 0, M | 0, 0) | 0;
    r = ob(P | 0, R | 0, r | 0, E | 0) | 0;
    R = E;
    P = Bb(t | 0, 0, K | 0, 0) | 0;
    P = ob(r | 0, R | 0, P | 0, E | 0) | 0;
    R = E;
    r = Bb(y | 0, 0, I | 0, 0) | 0;
    r = ob(P | 0, R | 0, r | 0, E | 0) | 0;
    R = E;
    P = Bb(u | 0, 0, G | 0, 0) | 0;
    P = ob(r | 0, R | 0, P | 0, E | 0) | 0;
    n = ob(P | 0, E | 0, v | 0, n | 0) | 0;
    v = n & 67108863;
    n = qb(n | 0, E | 0, 26) | 0;
    P = E;
    R = Bb(v | 0, 0, 15632, 0) | 0;
    r = E;
    w = ob(S | 0, q | 0, f | 0, w | 0) | 0;
    r = ob(w | 0, E | 0, R | 0, r | 0) | 0;
    d = ob(r | 0, E | 0, s | 0, d | 0) | 0;
    s = qb(d | 0, E | 0, 26) | 0;
    r = E;
    v = rb(v | 0, 0, 10) | 0;
    R = E;
    w = Bb(G | 0, 0, x | 0, 0) | 0;
    f = E;
    q = Bb(D | 0, 0, N | 0, 0) | 0;
    f = ob(q | 0, E | 0, w | 0, f | 0) | 0;
    w = E;
    q = Bb(B | 0, 0, J | 0, 0) | 0;
    q = ob(f | 0, w | 0, q | 0, E | 0) | 0;
    w = E;
    f = Bb(z | 0, 0, H | 0, 0) | 0;
    f = ob(q | 0, w | 0, f | 0, E | 0) | 0;
    w = E;
    q = Bb(F | 0, 0, m | 0, 0) | 0;
    S = E;
    b = Bb(C | 0, 0, L | 0, 0) | 0;
    S = ob(b | 0, E | 0, q | 0, S | 0) | 0;
    q = E;
    b = Bb(A | 0, 0, O | 0, 0) | 0;
    b = ob(S | 0, q | 0, b | 0, E | 0) | 0;
    q = E;
    S = Bb(t | 0, 0, M | 0, 0) | 0;
    S = ob(b | 0, q | 0, S | 0, E | 0) | 0;
    q = E;
    b = Bb(y | 0, 0, K | 0, 0) | 0;
    b = ob(S | 0, q | 0, b | 0, E | 0) | 0;
    q = E;
    S = Bb(u | 0, 0, I | 0, 0) | 0;
    S = ob(b | 0, q | 0, S | 0, E | 0) | 0;
    P = ob(S | 0, E | 0, n | 0, P | 0) | 0;
    n = P & 67108863;
    P = qb(P | 0, E | 0, 26) | 0;
    S = E;
    q = Bb(n | 0, 0, 15632, 0) | 0;
    b = E;
    R = ob(f | 0, w | 0, v | 0, R | 0) | 0;
    b = ob(R | 0, E | 0, q | 0, b | 0) | 0;
    r = ob(b | 0, E | 0, s | 0, r | 0) | 0;
    s = qb(r | 0, E | 0, 26) | 0;
    b = E;
    n = rb(n | 0, 0, 10) | 0;
    q = E;
    R = Bb(I | 0, 0, x | 0, 0) | 0;
    v = E;
    w = Bb(G | 0, 0, N | 0, 0) | 0;
    v = ob(w | 0, E | 0, R | 0, v | 0) | 0;
    R = E;
    w = Bb(D | 0, 0, J | 0, 0) | 0;
    w = ob(v | 0, R | 0, w | 0, E | 0) | 0;
    R = E;
    v = Bb(B | 0, 0, H | 0, 0) | 0;
    v = ob(w | 0, R | 0, v | 0, E | 0) | 0;
    R = E;
    w = Bb(z | 0, 0, F | 0, 0) | 0;
    w = ob(v | 0, R | 0, w | 0, E | 0) | 0;
    R = E;
    v = Bb(C | 0, 0, m | 0, 0) | 0;
    f = E;
    Q = Bb(A | 0, 0, L | 0, 0) | 0;
    f = ob(Q | 0, E | 0, v | 0, f | 0) | 0;
    v = E;
    Q = Bb(t | 0, 0, O | 0, 0) | 0;
    Q = ob(f | 0, v | 0, Q | 0, E | 0) | 0;
    v = E;
    f = Bb(y | 0, 0, M | 0, 0) | 0;
    f = ob(Q | 0, v | 0, f | 0, E | 0) | 0;
    v = E;
    Q = Bb(u | 0, 0, K | 0, 0) | 0;
    Q = ob(f | 0, v | 0, Q | 0, E | 0) | 0;
    S = ob(Q | 0, E | 0, P | 0, S | 0) | 0;
    P = S & 67108863;
    S = qb(S | 0, E | 0, 26) | 0;
    Q = E;
    v = Bb(P | 0, 0, 15632, 0) | 0;
    f = E;
    q = ob(w | 0, R | 0, n | 0, q | 0) | 0;
    f = ob(q | 0, E | 0, v | 0, f | 0) | 0;
    b = ob(f | 0, E | 0, s | 0, b | 0) | 0;
    s = qb(b | 0, E | 0, 26) | 0;
    f = E;
    P = rb(P | 0, 0, 10) | 0;
    v = E;
    q = Bb(K | 0, 0, x | 0, 0) | 0;
    n = E;
    R = Bb(I | 0, 0, N | 0, 0) | 0;
    n = ob(R | 0, E | 0, q | 0, n | 0) | 0;
    q = E;
    R = Bb(G | 0, 0, J | 0, 0) | 0;
    R = ob(n | 0, q | 0, R | 0, E | 0) | 0;
    q = E;
    n = Bb(D | 0, 0, H | 0, 0) | 0;
    n = ob(R | 0, q | 0, n | 0, E | 0) | 0;
    q = E;
    R = Bb(B | 0, 0, F | 0, 0) | 0;
    R = ob(n | 0, q | 0, R | 0, E | 0) | 0;
    q = E;
    n = Bb(z | 0, 0, C | 0, 0) | 0;
    n = ob(R | 0, q | 0, n | 0, E | 0) | 0;
    q = E;
    R = Bb(A | 0, 0, m | 0, 0) | 0;
    w = E;
    p = Bb(t | 0, 0, L | 0, 0) | 0;
    w = ob(p | 0, E | 0, R | 0, w | 0) | 0;
    R = E;
    p = Bb(y | 0, 0, O | 0, 0) | 0;
    p = ob(w | 0, R | 0, p | 0, E | 0) | 0;
    R = E;
    w = Bb(u | 0, 0, M | 0, 0) | 0;
    w = ob(p | 0, R | 0, w | 0, E | 0) | 0;
    Q = ob(w | 0, E | 0, S | 0, Q | 0) | 0;
    S = Q & 67108863;
    Q = qb(Q | 0, E | 0, 26) | 0;
    w = E;
    R = Bb(S | 0, 0, 15632, 0) | 0;
    p = E;
    v = ob(n | 0, q | 0, P | 0, v | 0) | 0;
    p = ob(v | 0, E | 0, R | 0, p | 0) | 0;
    f = ob(p | 0, E | 0, s | 0, f | 0) | 0;
    s = qb(f | 0, E | 0, 26) | 0;
    p = E;
    S = rb(S | 0, 0, 10) | 0;
    R = E;
    v = Bb(M | 0, 0, x | 0, 0) | 0;
    P = E;
    q = Bb(K | 0, 0, N | 0, 0) | 0;
    P = ob(q | 0, E | 0, v | 0, P | 0) | 0;
    v = E;
    q = Bb(I | 0, 0, J | 0, 0) | 0;
    q = ob(P | 0, v | 0, q | 0, E | 0) | 0;
    v = E;
    P = Bb(G | 0, 0, H | 0, 0) | 0;
    P = ob(q | 0, v | 0, P | 0, E | 0) | 0;
    v = E;
    q = Bb(D | 0, 0, F | 0, 0) | 0;
    q = ob(P | 0, v | 0, q | 0, E | 0) | 0;
    v = E;
    P = Bb(B | 0, 0, C | 0, 0) | 0;
    P = ob(q | 0, v | 0, P | 0, E | 0) | 0;
    v = E;
    q = Bb(z | 0, 0, A | 0, 0) | 0;
    q = ob(P | 0, v | 0, q | 0, E | 0) | 0;
    v = E;
    P = Bb(t | 0, 0, m | 0, 0) | 0;
    n = E;
    j = Bb(y | 0, 0, L | 0, 0) | 0;
    n = ob(j | 0, E | 0, P | 0, n | 0) | 0;
    P = E;
    j = Bb(u | 0, 0, O | 0, 0) | 0;
    j = ob(n | 0, P | 0, j | 0, E | 0) | 0;
    w = ob(j | 0, E | 0, Q | 0, w | 0) | 0;
    Q = w & 67108863;
    w = qb(w | 0, E | 0, 26) | 0;
    j = E;
    P = Bb(Q | 0, 0, 15632, 0) | 0;
    n = E;
    R = ob(q | 0, v | 0, S | 0, R | 0) | 0;
    n = ob(R | 0, E | 0, P | 0, n | 0) | 0;
    p = ob(n | 0, E | 0, s | 0, p | 0) | 0;
    s = qb(p | 0, E | 0, 26) | 0;
    n = E;
    Q = rb(Q | 0, 0, 10) | 0;
    P = E;
    R = Bb(O | 0, 0, x | 0, 0) | 0;
    S = E;
    v = Bb(M | 0, 0, N | 0, 0) | 0;
    S = ob(v | 0, E | 0, R | 0, S | 0) | 0;
    R = E;
    v = Bb(K | 0, 0, J | 0, 0) | 0;
    v = ob(S | 0, R | 0, v | 0, E | 0) | 0;
    R = E;
    S = Bb(I | 0, 0, H | 0, 0) | 0;
    S = ob(v | 0, R | 0, S | 0, E | 0) | 0;
    R = E;
    v = Bb(G | 0, 0, F | 0, 0) | 0;
    v = ob(S | 0, R | 0, v | 0, E | 0) | 0;
    R = E;
    S = Bb(D | 0, 0, C | 0, 0) | 0;
    S = ob(v | 0, R | 0, S | 0, E | 0) | 0;
    R = E;
    v = Bb(B | 0, 0, A | 0, 0) | 0;
    v = ob(S | 0, R | 0, v | 0, E | 0) | 0;
    R = E;
    S = Bb(z | 0, 0, t | 0, 0) | 0;
    S = ob(v | 0, R | 0, S | 0, E | 0) | 0;
    R = E;
    v = Bb(y | 0, 0, m | 0, 0) | 0;
    q = E;
    h = Bb(u | 0, 0, L | 0, 0) | 0;
    q = ob(h | 0, E | 0, v | 0, q | 0) | 0;
    j = ob(q | 0, E | 0, w | 0, j | 0) | 0;
    w = j & 67108863;
    j = qb(j | 0, E | 0, 26) | 0;
    q = E;
    v = Bb(w | 0, 0, 15632, 0) | 0;
    h = E;
    P = ob(S | 0, R | 0, Q | 0, P | 0) | 0;
    h = ob(P | 0, E | 0, v | 0, h | 0) | 0;
    n = ob(h | 0, E | 0, s | 0, n | 0) | 0;
    s = qb(n | 0, E | 0, 26) | 0;
    h = E;
    w = rb(w | 0, 0, 10) | 0;
    v = E;
    x = Bb(L | 0, 0, x | 0, 0) | 0;
    L = E;
    N = Bb(O | 0, 0, N | 0, 0) | 0;
    L = ob(N | 0, E | 0, x | 0, L | 0) | 0;
    x = E;
    J = Bb(M | 0, 0, J | 0, 0) | 0;
    J = ob(L | 0, x | 0, J | 0, E | 0) | 0;
    x = E;
    H = Bb(K | 0, 0, H | 0, 0) | 0;
    H = ob(J | 0, x | 0, H | 0, E | 0) | 0;
    x = E;
    F = Bb(I | 0, 0, F | 0, 0) | 0;
    F = ob(H | 0, x | 0, F | 0, E | 0) | 0;
    x = E;
    C = Bb(G | 0, 0, C | 0, 0) | 0;
    C = ob(F | 0, x | 0, C | 0, E | 0) | 0;
    x = E;
    A = Bb(D | 0, 0, A | 0, 0) | 0;
    A = ob(C | 0, x | 0, A | 0, E | 0) | 0;
    x = E;
    t = Bb(B | 0, 0, t | 0, 0) | 0;
    t = ob(A | 0, x | 0, t | 0, E | 0) | 0;
    x = E;
    y = Bb(z | 0, 0, y | 0, 0) | 0;
    y = ob(t | 0, x | 0, y | 0, E | 0) | 0;
    x = E;
    m = Bb(u | 0, 0, m | 0, 0) | 0;
    m = ob(j | 0, q | 0, m | 0, E | 0) | 0;
    q = m & 67108863;
    m = qb(m | 0, E | 0, 26) | 0;
    j = E;
    u = Bb(q | 0, 0, 15632, 0) | 0;
    t = E;
    v = ob(y | 0, x | 0, w | 0, v | 0) | 0;
    t = ob(v | 0, E | 0, u | 0, t | 0) | 0;
    h = ob(t | 0, E | 0, s | 0, h | 0) | 0;
    c[(a + 12) >> 2] = r & 67108863;
    c[(a + 16) >> 2] = b & 67108863;
    c[(a + 20) >> 2] = f & 67108863;
    c[(a + 24) >> 2] = p & 67108863;
    c[(a + 28) >> 2] = n & 67108863;
    c[(a + 32) >> 2] = h & 67108863;
    h = qb(h | 0, E | 0, 26) | 0;
    n = E;
    q = rb(q | 0, 0, 10) | 0;
    p = E;
    f = Bb(m | 0, j | 0, 15632, 0) | 0;
    b = E;
    o = ob(q | 0, p | 0, (o & 67108863) | 0, 0) | 0;
    b = ob(o | 0, E | 0, f | 0, b | 0) | 0;
    n = ob(b | 0, E | 0, h | 0, n | 0) | 0;
    c[(a + 36) >> 2] = n & 4194303;
    n = qb(n | 0, E | 0, 22) | 0;
    h = E;
    j = rb(m | 0, j | 0, 14) | 0;
    j = ob(n | 0, h | 0, j | 0, E | 0) | 0;
    h = E;
    n = Bb(j | 0, h | 0, 977, 0) | 0;
    m = E;
    b = ob(n | 0, m | 0, (l & 67108863) | 0, 0) | 0;
    f = E;
    k = ob(n | 0, m | 0, l | 0, k | 0) | 0;
    c[a >> 2] = k & 67108863;
    f = qb(b | 0, f | 0, 26) | 0;
    b = E;
    h = rb(j | 0, h | 0, 6) | 0;
    g = ob(h | 0, E | 0, (g & 67108863) | 0, 0) | 0;
    b = ob(g | 0, E | 0, f | 0, b | 0) | 0;
    c[(a + 4) >> 2] = b & 67108863;
    b = qb(b | 0, E | 0, 26) | 0;
    d = ob(b | 0, E | 0, (d & 67108863) | 0, 0) | 0;
    c[(a + 8) >> 2] = d;
    i = e;
    return;
  }
  function Wa(a) {
    a = a | 0;
    var b = 0,
      d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0;
    g = i;
    b = c[(a + 36) >> 2] | 0;
    d = b >>> 22;
    e = (((d * 977) | 0) + (c[a >> 2] | 0)) | 0;
    f = e & 67108863;
    if (!(((f | 0) == 0) | ((f | 0) == 67107887))) {
      a = 0;
      i = g;
      return a | 0;
    }
    o = (((e >>> 26) | (d << 6)) + (c[(a + 4) >> 2] | 0)) | 0;
    n = ((o >>> 26) + (c[(a + 8) >> 2] | 0)) | 0;
    m = ((n >>> 26) + (c[(a + 12) >> 2] | 0)) | 0;
    l = ((m >>> 26) + (c[(a + 16) >> 2] | 0)) | 0;
    k = ((l >>> 26) + (c[(a + 20) >> 2] | 0)) | 0;
    j = ((k >>> 26) + (c[(a + 24) >> 2] | 0)) | 0;
    h = ((j >>> 26) + (c[(a + 28) >> 2] | 0)) | 0;
    j = j & 67108863;
    d = ((h >>> 26) + (c[(a + 32) >> 2] | 0)) | 0;
    a = ((d >>> 26) + (b & 4194303)) | 0;
    a =
      (((o ^ 64) & (e ^ 976) & n & m & l & k & j & h & d & (a ^ 62914560)) |
        0) ==
      67108863
        ? 1
        : ((o & 67108863) |
            f |
            (n & 67108863) |
            (m & 67108863) |
            (l & 67108863) |
            (k & 67108863) |
            j |
            (h & 67108863) |
            (d & 67108863) |
            a |
            0) ==
          0;
    i = g;
    return a | 0;
  }
  function Xa(a, b, d) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0;
    e = i;
    i = (i + 64) | 0;
    f = e;
    H = c[b >> 2] | 0;
    m = c[d >> 2] | 0;
    C = Bb(m | 0, 0, H | 0, 0) | 0;
    B = E;
    c[f >> 2] = C;
    C = (d + 4) | 0;
    t = c[C >> 2] | 0;
    D = Bb(t | 0, 0, H | 0, 0) | 0;
    B = (D + B) | 0;
    D = (((B >>> 0 < D >>> 0) & 1) + E) | 0;
    J = (b + 4) | 0;
    A = c[J >> 2] | 0;
    j = Bb(m | 0, 0, A | 0, 0) | 0;
    B = (j + B) | 0;
    j = (((B >>> 0 < j >>> 0) & 1) + E) | 0;
    D = (D + j) | 0;
    c[(f + 4) >> 2] = B;
    B = (d + 8) | 0;
    q = c[B >> 2] | 0;
    o = Bb(q | 0, 0, H | 0, 0) | 0;
    s = (D + o) | 0;
    o = (((s >>> 0 < o >>> 0) & 1) + E) | 0;
    j = (o + ((D >>> 0 < j >>> 0) & 1)) | 0;
    D = Bb(t | 0, 0, A | 0, 0) | 0;
    s = (s + D) | 0;
    D = (((s >>> 0 < D >>> 0) & 1) + E) | 0;
    w = (j + D) | 0;
    v = (b + 8) | 0;
    l = c[v >> 2] | 0;
    m = Bb(m | 0, 0, l | 0, 0) | 0;
    s = (s + m) | 0;
    m = (((s >>> 0 < m >>> 0) & 1) + E) | 0;
    y = (w + m) | 0;
    c[(f + 8) >> 2] = s;
    s = (d + 12) | 0;
    I = c[s >> 2] | 0;
    H = Bb(I | 0, 0, H | 0, 0) | 0;
    u = (y + H) | 0;
    H = (((u >>> 0 < H >>> 0) & 1) + E) | 0;
    m =
      (((w >>> 0 < D >>> 0) & 1) +
        ((j >>> 0 < o >>> 0) & 1) +
        ((y >>> 0 < m >>> 0) & 1) +
        H) |
      0;
    A = Bb(q | 0, 0, A | 0, 0) | 0;
    u = (u + A) | 0;
    A = (((u >>> 0 < A >>> 0) & 1) + E) | 0;
    q = (m + A) | 0;
    l = Bb(t | 0, 0, l | 0, 0) | 0;
    u = (u + l) | 0;
    l = (((u >>> 0 < l >>> 0) & 1) + E) | 0;
    t = (q + l) | 0;
    y = (b + 12) | 0;
    o = c[y >> 2] | 0;
    j = c[d >> 2] | 0;
    D = Bb(j | 0, 0, o | 0, 0) | 0;
    u = (u + D) | 0;
    D = (((u >>> 0 < D >>> 0) & 1) + E) | 0;
    w = (t + D) | 0;
    c[(f + 12) >> 2] = u;
    u = c[b >> 2] | 0;
    p = (d + 16) | 0;
    z = c[p >> 2] | 0;
    M = Bb(z | 0, 0, u | 0, 0) | 0;
    k = (w + M) | 0;
    M = (((k >>> 0 < M >>> 0) & 1) + E) | 0;
    D =
      (((q >>> 0 < A >>> 0) & 1) +
        ((m >>> 0 < H >>> 0) & 1) +
        ((t >>> 0 < l >>> 0) & 1) +
        ((w >>> 0 < D >>> 0) & 1) +
        M) |
      0;
    w = c[J >> 2] | 0;
    I = Bb(I | 0, 0, w | 0, 0) | 0;
    k = (k + I) | 0;
    I = (((k >>> 0 < I >>> 0) & 1) + E) | 0;
    l = (D + I) | 0;
    t = c[v >> 2] | 0;
    H = c[B >> 2] | 0;
    m = Bb(H | 0, 0, t | 0, 0) | 0;
    k = (k + m) | 0;
    m = (((k >>> 0 < m >>> 0) & 1) + E) | 0;
    A = (l + m) | 0;
    q = c[C >> 2] | 0;
    o = Bb(q | 0, 0, o | 0, 0) | 0;
    k = (k + o) | 0;
    o = (((k >>> 0 < o >>> 0) & 1) + E) | 0;
    n = (A + o) | 0;
    r = (b + 16) | 0;
    h = c[r >> 2] | 0;
    j = Bb(j | 0, 0, h | 0, 0) | 0;
    k = (k + j) | 0;
    j = (((k >>> 0 < j >>> 0) & 1) + E) | 0;
    x = (n + j) | 0;
    c[(f + 16) >> 2] = k;
    k = (d + 20) | 0;
    u = Bb(c[k >> 2] | 0, 0, u | 0, 0) | 0;
    g = (x + u) | 0;
    u = (((g >>> 0 < u >>> 0) & 1) + E) | 0;
    j =
      (((l >>> 0 < I >>> 0) & 1) +
        ((D >>> 0 < M >>> 0) & 1) +
        ((A >>> 0 < m >>> 0) & 1) +
        ((n >>> 0 < o >>> 0) & 1) +
        ((x >>> 0 < j >>> 0) & 1) +
        u) |
      0;
    w = Bb(z | 0, 0, w | 0, 0) | 0;
    g = (g + w) | 0;
    w = (((g >>> 0 < w >>> 0) & 1) + E) | 0;
    z = (j + w) | 0;
    t = Bb(c[s >> 2] | 0, 0, t | 0, 0) | 0;
    g = (g + t) | 0;
    t = (((g >>> 0 < t >>> 0) & 1) + E) | 0;
    x = (z + t) | 0;
    o = c[y >> 2] | 0;
    H = Bb(H | 0, 0, o | 0, 0) | 0;
    g = (g + H) | 0;
    H = (((g >>> 0 < H >>> 0) & 1) + E) | 0;
    n = (x + H) | 0;
    h = Bb(q | 0, 0, h | 0, 0) | 0;
    g = (h + g) | 0;
    h = (((g >>> 0 < h >>> 0) & 1) + E) | 0;
    q = (h + n) | 0;
    m = (b + 20) | 0;
    A = c[m >> 2] | 0;
    M = Bb(c[d >> 2] | 0, 0, A | 0, 0) | 0;
    g = (M + g) | 0;
    M = (((g >>> 0 < M >>> 0) & 1) + E) | 0;
    D = (M + q) | 0;
    c[(f + 20) >> 2] = g;
    g = (d + 24) | 0;
    I = Bb(c[g >> 2] | 0, 0, c[b >> 2] | 0, 0) | 0;
    l = (D + I) | 0;
    I = (((l >>> 0 < I >>> 0) & 1) + E) | 0;
    M =
      (((z >>> 0 < w >>> 0) & 1) +
        ((j >>> 0 < u >>> 0) & 1) +
        ((x >>> 0 < t >>> 0) & 1) +
        ((n >>> 0 < H >>> 0) & 1) +
        ((q >>> 0 < h >>> 0) & 1) +
        ((D >>> 0 < M >>> 0) & 1) +
        I) |
      0;
    D = Bb(c[k >> 2] | 0, 0, c[J >> 2] | 0, 0) | 0;
    l = (l + D) | 0;
    D = (((l >>> 0 < D >>> 0) & 1) + E) | 0;
    h = (M + D) | 0;
    q = Bb(c[p >> 2] | 0, 0, c[v >> 2] | 0, 0) | 0;
    l = (l + q) | 0;
    q = (((l >>> 0 < q >>> 0) & 1) + E) | 0;
    H = (h + q) | 0;
    o = Bb(c[s >> 2] | 0, 0, o | 0, 0) | 0;
    l = (l + o) | 0;
    o = (((l >>> 0 < o >>> 0) & 1) + E) | 0;
    n = (H + o) | 0;
    t = Bb(c[B >> 2] | 0, 0, c[r >> 2] | 0, 0) | 0;
    l = (t + l) | 0;
    t = (((l >>> 0 < t >>> 0) & 1) + E) | 0;
    x = (t + n) | 0;
    A = Bb(c[C >> 2] | 0, 0, A | 0, 0) | 0;
    l = (A + l) | 0;
    A = (((l >>> 0 < A >>> 0) & 1) + E) | 0;
    u = (A + x) | 0;
    j = (b + 24) | 0;
    w = Bb(c[d >> 2] | 0, 0, c[j >> 2] | 0, 0) | 0;
    l = (w + l) | 0;
    w = (((l >>> 0 < w >>> 0) & 1) + E) | 0;
    z = (w + u) | 0;
    c[(f + 24) >> 2] = l;
    l = (d + 28) | 0;
    F = Bb(c[l >> 2] | 0, 0, c[b >> 2] | 0, 0) | 0;
    L = (z + F) | 0;
    F = (((L >>> 0 < F >>> 0) & 1) + E) | 0;
    w =
      (((h >>> 0 < D >>> 0) & 1) +
        ((M >>> 0 < I >>> 0) & 1) +
        ((H >>> 0 < q >>> 0) & 1) +
        ((n >>> 0 < o >>> 0) & 1) +
        ((x >>> 0 < t >>> 0) & 1) +
        ((u >>> 0 < A >>> 0) & 1) +
        ((z >>> 0 < w >>> 0) & 1) +
        F) |
      0;
    z = Bb(c[g >> 2] | 0, 0, c[J >> 2] | 0, 0) | 0;
    L = (L + z) | 0;
    z = (((L >>> 0 < z >>> 0) & 1) + E) | 0;
    A = (w + z) | 0;
    u = Bb(c[k >> 2] | 0, 0, c[v >> 2] | 0, 0) | 0;
    L = (L + u) | 0;
    u = (((L >>> 0 < u >>> 0) & 1) + E) | 0;
    t = (A + u) | 0;
    x = Bb(c[p >> 2] | 0, 0, c[y >> 2] | 0, 0) | 0;
    L = (L + x) | 0;
    x = (((L >>> 0 < x >>> 0) & 1) + E) | 0;
    o = (t + x) | 0;
    n = Bb(c[s >> 2] | 0, 0, c[r >> 2] | 0, 0) | 0;
    L = (n + L) | 0;
    n = (((L >>> 0 < n >>> 0) & 1) + E) | 0;
    q = (n + o) | 0;
    H = Bb(c[B >> 2] | 0, 0, c[m >> 2] | 0, 0) | 0;
    L = (H + L) | 0;
    H = (((L >>> 0 < H >>> 0) & 1) + E) | 0;
    I = (H + q) | 0;
    M = Bb(c[C >> 2] | 0, 0, c[j >> 2] | 0, 0) | 0;
    L = (M + L) | 0;
    M = (((L >>> 0 < M >>> 0) & 1) + E) | 0;
    D = (M + I) | 0;
    h = (b + 28) | 0;
    K = Bb(c[d >> 2] | 0, 0, c[h >> 2] | 0, 0) | 0;
    b = (K + L) | 0;
    K = (((b >>> 0 < K >>> 0) & 1) + E) | 0;
    L = (K + D) | 0;
    c[(f + 28) >> 2] = b;
    J = Bb(c[l >> 2] | 0, 0, c[J >> 2] | 0, 0) | 0;
    b = (L + J) | 0;
    J = (((b >>> 0 < J >>> 0) & 1) + E) | 0;
    K =
      (((A >>> 0 < z >>> 0) & 1) +
        ((w >>> 0 < F >>> 0) & 1) +
        ((t >>> 0 < u >>> 0) & 1) +
        ((o >>> 0 < x >>> 0) & 1) +
        ((q >>> 0 < n >>> 0) & 1) +
        ((I >>> 0 < H >>> 0) & 1) +
        ((D >>> 0 < M >>> 0) & 1) +
        ((L >>> 0 < K >>> 0) & 1) +
        J) |
      0;
    v = c[v >> 2] | 0;
    L = Bb(c[g >> 2] | 0, 0, v | 0, 0) | 0;
    b = (b + L) | 0;
    L = (((b >>> 0 < L >>> 0) & 1) + E) | 0;
    M = (K + L) | 0;
    D = c[y >> 2] | 0;
    H = Bb(c[k >> 2] | 0, 0, D | 0, 0) | 0;
    b = (b + H) | 0;
    H = (((b >>> 0 < H >>> 0) & 1) + E) | 0;
    I = (M + H) | 0;
    n = c[r >> 2] | 0;
    q = Bb(c[p >> 2] | 0, 0, n | 0, 0) | 0;
    b = (b + q) | 0;
    q = (((b >>> 0 < q >>> 0) & 1) + E) | 0;
    x = (I + q) | 0;
    d = c[m >> 2] | 0;
    o = Bb(c[s >> 2] | 0, 0, d | 0, 0) | 0;
    b = (o + b) | 0;
    o = (((b >>> 0 < o >>> 0) & 1) + E) | 0;
    u = (o + x) | 0;
    t = c[j >> 2] | 0;
    F = Bb(c[B >> 2] | 0, 0, t | 0, 0) | 0;
    b = (F + b) | 0;
    F = (((b >>> 0 < F >>> 0) & 1) + E) | 0;
    w = (F + u) | 0;
    z = c[h >> 2] | 0;
    C = Bb(c[C >> 2] | 0, 0, z | 0, 0) | 0;
    b = (C + b) | 0;
    C = (((b >>> 0 < C >>> 0) & 1) + E) | 0;
    A = (C + w) | 0;
    c[(f + 32) >> 2] = b;
    b = c[l >> 2] | 0;
    v = Bb(b | 0, 0, v | 0, 0) | 0;
    G = (A + v) | 0;
    v = (((G >>> 0 < v >>> 0) & 1) + E) | 0;
    C =
      (((M >>> 0 < L >>> 0) & 1) +
        ((K >>> 0 < J >>> 0) & 1) +
        ((I >>> 0 < H >>> 0) & 1) +
        ((x >>> 0 < q >>> 0) & 1) +
        ((u >>> 0 < o >>> 0) & 1) +
        ((w >>> 0 < F >>> 0) & 1) +
        ((A >>> 0 < C >>> 0) & 1) +
        v) |
      0;
    A = c[g >> 2] | 0;
    D = Bb(A | 0, 0, D | 0, 0) | 0;
    G = (G + D) | 0;
    D = (((G >>> 0 < D >>> 0) & 1) + E) | 0;
    F = (C + D) | 0;
    w = c[k >> 2] | 0;
    n = Bb(w | 0, 0, n | 0, 0) | 0;
    G = (G + n) | 0;
    n = (((G >>> 0 < n >>> 0) & 1) + E) | 0;
    o = (F + n) | 0;
    u = c[p >> 2] | 0;
    d = Bb(u | 0, 0, d | 0, 0) | 0;
    G = (G + d) | 0;
    d = (((G >>> 0 < d >>> 0) & 1) + E) | 0;
    q = (o + d) | 0;
    s = c[s >> 2] | 0;
    t = Bb(s | 0, 0, t | 0, 0) | 0;
    G = (t + G) | 0;
    t = (((G >>> 0 < t >>> 0) & 1) + E) | 0;
    x = (t + q) | 0;
    z = Bb(c[B >> 2] | 0, 0, z | 0, 0) | 0;
    G = (z + G) | 0;
    z = (((G >>> 0 < z >>> 0) & 1) + E) | 0;
    B = (z + x) | 0;
    c[(f + 36) >> 2] = G;
    y = Bb(b | 0, 0, c[y >> 2] | 0, 0) | 0;
    b = (B + y) | 0;
    y = (((b >>> 0 < y >>> 0) & 1) + E) | 0;
    z =
      (((F >>> 0 < D >>> 0) & 1) +
        ((C >>> 0 < v >>> 0) & 1) +
        ((o >>> 0 < n >>> 0) & 1) +
        ((q >>> 0 < d >>> 0) & 1) +
        ((x >>> 0 < t >>> 0) & 1) +
        ((B >>> 0 < z >>> 0) & 1) +
        y) |
      0;
    r = c[r >> 2] | 0;
    A = Bb(A | 0, 0, r | 0, 0) | 0;
    b = (b + A) | 0;
    A = (((b >>> 0 < A >>> 0) & 1) + E) | 0;
    B = (z + A) | 0;
    t = c[m >> 2] | 0;
    w = Bb(w | 0, 0, t | 0, 0) | 0;
    b = (b + w) | 0;
    w = (((b >>> 0 < w >>> 0) & 1) + E) | 0;
    x = (B + w) | 0;
    d = c[j >> 2] | 0;
    u = Bb(u | 0, 0, d | 0, 0) | 0;
    b = (b + u) | 0;
    u = (((b >>> 0 < u >>> 0) & 1) + E) | 0;
    q = (x + u) | 0;
    n = c[h >> 2] | 0;
    s = Bb(s | 0, 0, n | 0, 0) | 0;
    b = (s + b) | 0;
    s = (((b >>> 0 < s >>> 0) & 1) + E) | 0;
    o = (s + q) | 0;
    c[(f + 40) >> 2] = b;
    b = c[l >> 2] | 0;
    r = Bb(b | 0, 0, r | 0, 0) | 0;
    v = (o + r) | 0;
    r = (((v >>> 0 < r >>> 0) & 1) + E) | 0;
    s =
      (((B >>> 0 < A >>> 0) & 1) +
        ((z >>> 0 < y >>> 0) & 1) +
        ((x >>> 0 < w >>> 0) & 1) +
        ((q >>> 0 < u >>> 0) & 1) +
        ((o >>> 0 < s >>> 0) & 1) +
        r) |
      0;
    o = c[g >> 2] | 0;
    t = Bb(o | 0, 0, t | 0, 0) | 0;
    v = (v + t) | 0;
    t = (((v >>> 0 < t >>> 0) & 1) + E) | 0;
    u = (s + t) | 0;
    k = c[k >> 2] | 0;
    d = Bb(k | 0, 0, d | 0, 0) | 0;
    v = (v + d) | 0;
    d = (((v >>> 0 < d >>> 0) & 1) + E) | 0;
    q = (u + d) | 0;
    n = Bb(c[p >> 2] | 0, 0, n | 0, 0) | 0;
    v = (v + n) | 0;
    n = (((v >>> 0 < n >>> 0) & 1) + E) | 0;
    p = (q + n) | 0;
    c[(f + 44) >> 2] = v;
    m = Bb(b | 0, 0, c[m >> 2] | 0, 0) | 0;
    b = (p + m) | 0;
    m = (((b >>> 0 < m >>> 0) & 1) + E) | 0;
    n =
      (((u >>> 0 < t >>> 0) & 1) +
        ((s >>> 0 < r >>> 0) & 1) +
        ((q >>> 0 < d >>> 0) & 1) +
        ((p >>> 0 < n >>> 0) & 1) +
        m) |
      0;
    j = c[j >> 2] | 0;
    o = Bb(o | 0, 0, j | 0, 0) | 0;
    b = (b + o) | 0;
    o = (((b >>> 0 < o >>> 0) & 1) + E) | 0;
    p = (n + o) | 0;
    d = c[h >> 2] | 0;
    k = Bb(k | 0, 0, d | 0, 0) | 0;
    b = (b + k) | 0;
    k = (((b >>> 0 < k >>> 0) & 1) + E) | 0;
    h = (p + k) | 0;
    c[(f + 48) >> 2] = b;
    b = c[l >> 2] | 0;
    j = Bb(b | 0, 0, j | 0, 0) | 0;
    l = (h + j) | 0;
    j = (((l >>> 0 < j >>> 0) & 1) + E) | 0;
    k =
      (((p >>> 0 < o >>> 0) & 1) +
        ((n >>> 0 < m >>> 0) & 1) +
        ((h >>> 0 < k >>> 0) & 1) +
        j) |
      0;
    g = Bb(c[g >> 2] | 0, 0, d | 0, 0) | 0;
    l = (l + g) | 0;
    g = (((l >>> 0 < g >>> 0) & 1) + E) | 0;
    h = (k + g) | 0;
    c[(f + 52) >> 2] = l;
    d = Bb(b | 0, 0, d | 0, 0) | 0;
    b = (h + d) | 0;
    c[(f + 56) >> 2] = b;
    c[(f + 60) >> 2] =
      ((k >>> 0 < j >>> 0) & 1) +
      E +
      ((h >>> 0 < g >>> 0) & 1) +
      ((b >>> 0 < d >>> 0) & 1);
    Ya(a, f);
    i = e;
    return;
  }
  function Ya(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      F = 0;
    d = i;
    t = c[(b + 32) >> 2] | 0;
    A = c[(b + 36) >> 2] | 0;
    g = c[(b + 40) >> 2] | 0;
    u = c[(b + 44) >> 2] | 0;
    s = c[(b + 48) >> 2] | 0;
    C = c[(b + 52) >> 2] | 0;
    q = c[(b + 56) >> 2] | 0;
    z = c[(b + 60) >> 2] | 0;
    n = c[b >> 2] | 0;
    p = Bb(t | 0, 0, 801750719, 0) | 0;
    n = (n + p) | 0;
    y = c[(b + 4) >> 2] | 0;
    p = (y + E + ((n >>> 0 < p >>> 0) & 1)) | 0;
    x = Bb(A | 0, 0, 801750719, 0) | 0;
    h = (p + x) | 0;
    x = (((h >>> 0 < x >>> 0) & 1) + E) | 0;
    y = (x + ((p >>> 0 < y >>> 0) & 1)) | 0;
    p = Bb(t | 0, 0, 1076732275, 0) | 0;
    h = (h + p) | 0;
    p = (((h >>> 0 < p >>> 0) & 1) + E) | 0;
    B = (y + p) | 0;
    D = c[(b + 8) >> 2] | 0;
    e = (B + D) | 0;
    D = (e >>> 0 < D >>> 0) & 1;
    x = (((B >>> 0 < p >>> 0) & 1) + ((y >>> 0 < x >>> 0) & 1) + D) | 0;
    y = Bb(g | 0, 0, 801750719, 0) | 0;
    e = (e + y) | 0;
    y = (((e >>> 0 < y >>> 0) & 1) + E) | 0;
    p = (y + x) | 0;
    B = Bb(A | 0, 0, 1076732275, 0) | 0;
    e = (e + B) | 0;
    B = (((e >>> 0 < B >>> 0) & 1) + E) | 0;
    F = (p + B) | 0;
    l = Bb(t | 0, 0, 1354194884, 0) | 0;
    e = (e + l) | 0;
    l = (((e >>> 0 < l >>> 0) & 1) + E) | 0;
    k = (F + l) | 0;
    r = c[(b + 12) >> 2] | 0;
    w = (k + r) | 0;
    r = (w >>> 0 < r >>> 0) & 1;
    l =
      (((p >>> 0 < y >>> 0) & 1) +
        ((x >>> 0 < D >>> 0) & 1) +
        ((F >>> 0 < B >>> 0) & 1) +
        ((k >>> 0 < l >>> 0) & 1) +
        r) |
      0;
    k = Bb(u | 0, 0, 801750719, 0) | 0;
    w = (w + k) | 0;
    k = (((w >>> 0 < k >>> 0) & 1) + E) | 0;
    B = (k + l) | 0;
    F = Bb(g | 0, 0, 1076732275, 0) | 0;
    w = (w + F) | 0;
    F = (((w >>> 0 < F >>> 0) & 1) + E) | 0;
    D = (B + F) | 0;
    x = Bb(A | 0, 0, 1354194884, 0) | 0;
    w = (w + x) | 0;
    x = (((w >>> 0 < x >>> 0) & 1) + E) | 0;
    y = (D + x) | 0;
    p = Bb(t | 0, 0, 1162945305, 0) | 0;
    w = (w + p) | 0;
    p = (((w >>> 0 < p >>> 0) & 1) + E) | 0;
    m = (y + p) | 0;
    v = c[(b + 16) >> 2] | 0;
    o = (m + v) | 0;
    v = (o >>> 0 < v >>> 0) & 1;
    p =
      (((B >>> 0 < k >>> 0) & 1) +
        ((l >>> 0 < r >>> 0) & 1) +
        ((D >>> 0 < F >>> 0) & 1) +
        ((y >>> 0 < x >>> 0) & 1) +
        ((m >>> 0 < p >>> 0) & 1) +
        v) |
      0;
    m = Bb(s | 0, 0, 801750719, 0) | 0;
    o = (o + m) | 0;
    m = (((o >>> 0 < m >>> 0) & 1) + E) | 0;
    x = (m + p) | 0;
    y = Bb(u | 0, 0, 1076732275, 0) | 0;
    o = (o + y) | 0;
    y = (((o >>> 0 < y >>> 0) & 1) + E) | 0;
    F = (x + y) | 0;
    D = Bb(g | 0, 0, 1354194884, 0) | 0;
    o = (o + D) | 0;
    D = (((o >>> 0 < D >>> 0) & 1) + E) | 0;
    r = (F + D) | 0;
    l = Bb(A | 0, 0, 1162945305, 0) | 0;
    o = (o + l) | 0;
    l = (((o >>> 0 < l >>> 0) & 1) + E) | 0;
    k = (r + l) | 0;
    o = (o + t) | 0;
    t = (o >>> 0 < t >>> 0) & 1;
    B = (k + t) | 0;
    f = c[(b + 20) >> 2] | 0;
    j = (B + f) | 0;
    f = (j >>> 0 < f >>> 0) & 1;
    t =
      (((x >>> 0 < m >>> 0) & 1) +
        ((p >>> 0 < v >>> 0) & 1) +
        ((F >>> 0 < y >>> 0) & 1) +
        ((r >>> 0 < D >>> 0) & 1) +
        ((k >>> 0 < l >>> 0) & 1) +
        ((B >>> 0 < t >>> 0) & 1) +
        f) |
      0;
    B = Bb(C | 0, 0, 801750719, 0) | 0;
    j = (j + B) | 0;
    B = (((j >>> 0 < B >>> 0) & 1) + E) | 0;
    l = (B + t) | 0;
    k = Bb(s | 0, 0, 1076732275, 0) | 0;
    j = (j + k) | 0;
    k = (((j >>> 0 < k >>> 0) & 1) + E) | 0;
    D = (l + k) | 0;
    r = Bb(u | 0, 0, 1354194884, 0) | 0;
    j = (j + r) | 0;
    r = (((j >>> 0 < r >>> 0) & 1) + E) | 0;
    y = (D + r) | 0;
    F = Bb(g | 0, 0, 1162945305, 0) | 0;
    j = (j + F) | 0;
    F = (((j >>> 0 < F >>> 0) & 1) + E) | 0;
    v = (y + F) | 0;
    j = (j + A) | 0;
    A = (j >>> 0 < A >>> 0) & 1;
    p = (v + A) | 0;
    m = c[(b + 24) >> 2] | 0;
    x = (p + m) | 0;
    m = (x >>> 0 < m >>> 0) & 1;
    A =
      (((l >>> 0 < B >>> 0) & 1) +
        ((t >>> 0 < f >>> 0) & 1) +
        ((D >>> 0 < k >>> 0) & 1) +
        ((y >>> 0 < r >>> 0) & 1) +
        ((v >>> 0 < F >>> 0) & 1) +
        ((p >>> 0 < A >>> 0) & 1) +
        m) |
      0;
    p = Bb(q | 0, 0, 801750719, 0) | 0;
    x = (x + p) | 0;
    p = (((x >>> 0 < p >>> 0) & 1) + E) | 0;
    F = (p + A) | 0;
    v = Bb(C | 0, 0, 1076732275, 0) | 0;
    x = (x + v) | 0;
    v = (((x >>> 0 < v >>> 0) & 1) + E) | 0;
    r = (F + v) | 0;
    y = Bb(s | 0, 0, 1354194884, 0) | 0;
    x = (x + y) | 0;
    y = (((x >>> 0 < y >>> 0) & 1) + E) | 0;
    k = (r + y) | 0;
    D = Bb(u | 0, 0, 1162945305, 0) | 0;
    x = (x + D) | 0;
    D = (((x >>> 0 < D >>> 0) & 1) + E) | 0;
    f = (k + D) | 0;
    x = (x + g) | 0;
    g = (x >>> 0 < g >>> 0) & 1;
    t = (f + g) | 0;
    B = c[(b + 28) >> 2] | 0;
    l = (t + B) | 0;
    B = (l >>> 0 < B >>> 0) & 1;
    g =
      (((F >>> 0 < p >>> 0) & 1) +
        ((A >>> 0 < m >>> 0) & 1) +
        ((r >>> 0 < v >>> 0) & 1) +
        ((k >>> 0 < y >>> 0) & 1) +
        ((f >>> 0 < D >>> 0) & 1) +
        ((t >>> 0 < g >>> 0) & 1) +
        B) |
      0;
    t = Bb(z | 0, 0, 801750719, 0) | 0;
    l = (l + t) | 0;
    t = (((l >>> 0 < t >>> 0) & 1) + E) | 0;
    D = (t + g) | 0;
    f = Bb(q | 0, 0, 1076732275, 0) | 0;
    l = (l + f) | 0;
    f = (((l >>> 0 < f >>> 0) & 1) + E) | 0;
    y = (D + f) | 0;
    k = Bb(C | 0, 0, 1354194884, 0) | 0;
    l = (l + k) | 0;
    k = (((l >>> 0 < k >>> 0) & 1) + E) | 0;
    v = (y + k) | 0;
    r = Bb(s | 0, 0, 1162945305, 0) | 0;
    l = (l + r) | 0;
    r = (((l >>> 0 < r >>> 0) & 1) + E) | 0;
    m = (v + r) | 0;
    l = (l + u) | 0;
    u = (l >>> 0 < u >>> 0) & 1;
    b = (m + u) | 0;
    A = Bb(z | 0, 0, 1076732275, 0) | 0;
    p = (b + A) | 0;
    A = (((p >>> 0 < A >>> 0) & 1) + E) | 0;
    u =
      (((D >>> 0 < t >>> 0) & 1) +
        ((g >>> 0 < B >>> 0) & 1) +
        ((y >>> 0 < f >>> 0) & 1) +
        ((v >>> 0 < k >>> 0) & 1) +
        ((m >>> 0 < r >>> 0) & 1) +
        ((b >>> 0 < u >>> 0) & 1) +
        A) |
      0;
    b = Bb(q | 0, 0, 1354194884, 0) | 0;
    p = (p + b) | 0;
    b = (((p >>> 0 < b >>> 0) & 1) + E) | 0;
    r = (u + b) | 0;
    m = Bb(C | 0, 0, 1162945305, 0) | 0;
    p = (p + m) | 0;
    m = (((p >>> 0 < m >>> 0) & 1) + E) | 0;
    k = (r + m) | 0;
    p = (p + s) | 0;
    s = (p >>> 0 < s >>> 0) & 1;
    v = (k + s) | 0;
    f = Bb(z | 0, 0, 1354194884, 0) | 0;
    y = (v + f) | 0;
    f = (((y >>> 0 < f >>> 0) & 1) + E) | 0;
    s =
      (((r >>> 0 < b >>> 0) & 1) +
        ((u >>> 0 < A >>> 0) & 1) +
        ((k >>> 0 < m >>> 0) & 1) +
        ((v >>> 0 < s >>> 0) & 1) +
        f) |
      0;
    v = Bb(q | 0, 0, 1162945305, 0) | 0;
    y = (y + v) | 0;
    v = (((y >>> 0 < v >>> 0) & 1) + E) | 0;
    m = (s + v) | 0;
    y = (y + C) | 0;
    C = (y >>> 0 < C >>> 0) & 1;
    k = (m + C) | 0;
    A = Bb(z | 0, 0, 1162945305, 0) | 0;
    u = (k + A) | 0;
    A = (((u >>> 0 < A >>> 0) & 1) + E) | 0;
    C =
      (((m >>> 0 < v >>> 0) & 1) +
        ((s >>> 0 < f >>> 0) & 1) +
        ((k >>> 0 < C >>> 0) & 1) +
        A) |
      0;
    u = (u + q) | 0;
    q = (u >>> 0 < q >>> 0) & 1;
    k = (C + q) | 0;
    f = (k + z) | 0;
    z =
      (((k >>> 0 < q >>> 0) & 1) +
        ((C >>> 0 < A >>> 0) & 1) +
        ((f >>> 0 < z >>> 0) & 1)) |
      0;
    A = Bb(p | 0, 0, 801750719, 0) | 0;
    n = (A + n) | 0;
    A = (E + h + ((n >>> 0 < A >>> 0) & 1)) | 0;
    C = Bb(y | 0, 0, 801750719, 0) | 0;
    q = (C + A) | 0;
    C = (((q >>> 0 < C >>> 0) & 1) + E) | 0;
    h = (C + ((A >>> 0 < h >>> 0) & 1)) | 0;
    A = Bb(p | 0, 0, 1076732275, 0) | 0;
    q = (q + A) | 0;
    A = (((q >>> 0 < A >>> 0) & 1) + E) | 0;
    k = (h + A) | 0;
    s = (k + e) | 0;
    e = (s >>> 0 < e >>> 0) & 1;
    C = (((k >>> 0 < A >>> 0) & 1) + ((h >>> 0 < C >>> 0) & 1) + e) | 0;
    h = Bb(u | 0, 0, 801750719, 0) | 0;
    s = (s + h) | 0;
    h = (((s >>> 0 < h >>> 0) & 1) + E) | 0;
    A = (h + C) | 0;
    k = Bb(y | 0, 0, 1076732275, 0) | 0;
    s = (s + k) | 0;
    k = (((s >>> 0 < k >>> 0) & 1) + E) | 0;
    v = (A + k) | 0;
    m = Bb(p | 0, 0, 1354194884, 0) | 0;
    s = (s + m) | 0;
    m = (((s >>> 0 < m >>> 0) & 1) + E) | 0;
    b = (v + m) | 0;
    r = (b + w) | 0;
    w = (r >>> 0 < w >>> 0) & 1;
    m =
      (((A >>> 0 < h >>> 0) & 1) +
        ((C >>> 0 < e >>> 0) & 1) +
        ((v >>> 0 < k >>> 0) & 1) +
        ((b >>> 0 < m >>> 0) & 1) +
        w) |
      0;
    b = Bb(f | 0, 0, 801750719, 0) | 0;
    r = (r + b) | 0;
    b = (((r >>> 0 < b >>> 0) & 1) + E) | 0;
    k = (b + m) | 0;
    v = Bb(u | 0, 0, 1076732275, 0) | 0;
    r = (r + v) | 0;
    v = (((r >>> 0 < v >>> 0) & 1) + E) | 0;
    e = (k + v) | 0;
    C = Bb(y | 0, 0, 1354194884, 0) | 0;
    r = (r + C) | 0;
    C = (((r >>> 0 < C >>> 0) & 1) + E) | 0;
    h = (e + C) | 0;
    A = Bb(p | 0, 0, 1162945305, 0) | 0;
    r = (r + A) | 0;
    A = (((r >>> 0 < A >>> 0) & 1) + E) | 0;
    B = (h + A) | 0;
    g = (B + o) | 0;
    o = (g >>> 0 < o >>> 0) & 1;
    A =
      (((k >>> 0 < b >>> 0) & 1) +
        ((m >>> 0 < w >>> 0) & 1) +
        ((e >>> 0 < v >>> 0) & 1) +
        ((h >>> 0 < C >>> 0) & 1) +
        ((B >>> 0 < A >>> 0) & 1) +
        o) |
      0;
    B = Bb(z | 0, 0, 801750719, 0) | 0;
    g = (g + B) | 0;
    B = (((g >>> 0 < B >>> 0) & 1) + E) | 0;
    C = (B + A) | 0;
    h = Bb(f | 0, 0, 1076732275, 0) | 0;
    g = (g + h) | 0;
    h = (((g >>> 0 < h >>> 0) & 1) + E) | 0;
    v = (C + h) | 0;
    e = Bb(u | 0, 0, 1354194884, 0) | 0;
    g = (g + e) | 0;
    e = (((g >>> 0 < e >>> 0) & 1) + E) | 0;
    w = (v + e) | 0;
    m = Bb(y | 0, 0, 1162945305, 0) | 0;
    g = (g + m) | 0;
    m = (((g >>> 0 < m >>> 0) & 1) + E) | 0;
    b = (w + m) | 0;
    g = (g + p) | 0;
    p = (g >>> 0 < p >>> 0) & 1;
    k = (b + p) | 0;
    t = (k + j) | 0;
    j = (t >>> 0 < j >>> 0) & 1;
    p =
      (((C >>> 0 < B >>> 0) & 1) +
        ((A >>> 0 < o >>> 0) & 1) +
        ((v >>> 0 < h >>> 0) & 1) +
        ((w >>> 0 < e >>> 0) & 1) +
        ((b >>> 0 < m >>> 0) & 1) +
        ((k >>> 0 < p >>> 0) & 1) +
        j) |
      0;
    k = Bb(z | 0, 0, 1076732275, 0) | 0;
    t = (t + k) | 0;
    k = (((t >>> 0 < k >>> 0) & 1) + E) | 0;
    m = (k + p) | 0;
    b = Bb(f | 0, 0, 1354194884, 0) | 0;
    t = (t + b) | 0;
    b = (((t >>> 0 < b >>> 0) & 1) + E) | 0;
    e = (m + b) | 0;
    w = Bb(u | 0, 0, 1162945305, 0) | 0;
    t = (t + w) | 0;
    w = (((t >>> 0 < w >>> 0) & 1) + E) | 0;
    h = (e + w) | 0;
    t = (t + y) | 0;
    y = (t >>> 0 < y >>> 0) & 1;
    v = (h + y) | 0;
    o = (v + x) | 0;
    x = (o >>> 0 < x >>> 0) & 1;
    y =
      (((m >>> 0 < k >>> 0) & 1) +
        ((p >>> 0 < j >>> 0) & 1) +
        ((e >>> 0 < b >>> 0) & 1) +
        ((h >>> 0 < w >>> 0) & 1) +
        ((v >>> 0 < y >>> 0) & 1) +
        x) |
      0;
    v = Bb(z | 0, 0, 1354194884, 0) | 0;
    o = (o + v) | 0;
    v = (((o >>> 0 < v >>> 0) & 1) + E) | 0;
    w = (v + y) | 0;
    h = Bb(f | 0, 0, 1162945305, 0) | 0;
    o = (o + h) | 0;
    h = (((o >>> 0 < h >>> 0) & 1) + E) | 0;
    b = (w + h) | 0;
    o = (o + u) | 0;
    u = (o >>> 0 < u >>> 0) & 1;
    e = (b + u) | 0;
    j = (e + l) | 0;
    p = Bb(z | 0, 0, 1162945305, 0) | 0;
    k = (j + p) | 0;
    m = (k + f) | 0;
    f =
      (E +
        z +
        ((y >>> 0 < x >>> 0) & 1) +
        ((w >>> 0 < v >>> 0) & 1) +
        ((b >>> 0 < h >>> 0) & 1) +
        ((e >>> 0 < u >>> 0) & 1) +
        ((j >>> 0 < l >>> 0) & 1) +
        ((k >>> 0 < p >>> 0) & 1) +
        ((m >>> 0 < f >>> 0) & 1)) |
      0;
    p = Bb(f | 0, 0, 801750719, 0) | 0;
    n = ob(p | 0, E | 0, n | 0, 0) | 0;
    p = E;
    c[a >> 2] = n;
    k = Bb(f | 0, 0, 1076732275, 0) | 0;
    q = ob(k | 0, E | 0, q | 0, 0) | 0;
    p = ob(q | 0, E | 0, p | 0, 0) | 0;
    q = E;
    k = (a + 4) | 0;
    c[k >> 2] = p;
    l = Bb(f | 0, 0, 1354194884, 0) | 0;
    s = ob(l | 0, E | 0, s | 0, 0) | 0;
    q = ob(s | 0, E | 0, q | 0, 0) | 0;
    s = E;
    l = (a + 8) | 0;
    c[l >> 2] = q;
    j = Bb(f | 0, 0, 1162945305, 0) | 0;
    r = ob(j | 0, E | 0, r | 0, 0) | 0;
    s = ob(r | 0, E | 0, s | 0, 0) | 0;
    r = E;
    j = (a + 12) | 0;
    c[j >> 2] = s;
    g = ob(f | 0, 0, g | 0, 0) | 0;
    r = ob(g | 0, E | 0, r | 0, 0) | 0;
    g = (a + 16) | 0;
    c[g >> 2] = r;
    t = ob(E | 0, 0, t | 0, 0) | 0;
    f = (a + 20) | 0;
    c[f >> 2] = t;
    o = ob(E | 0, 0, o | 0, 0) | 0;
    u = E;
    e = (a + 24) | 0;
    c[e >> 2] = o;
    m = ob(u | 0, 0, m | 0, 0) | 0;
    h = E;
    b = (a + 28) | 0;
    c[b >> 2] = m;
    o = (r >>> 0 < 4294967294) | ((t | 0) != -1) | (((m & o) | 0) != -1);
    r = ((r | 0) == -1) & 1;
    m = ((o | (r ^ 1)) & (s >>> 0 < 3132021990)) | o;
    o = ((s >>> 0 > 3132021990) & ~m) | (r & ~o);
    m = ((q >>> 0 < 2940772411) & ~o) | m;
    o = ((q >>> 0 > 2940772411) & ~m) | o;
    m = ~(((p >>> 0 < 3218235020) & ~o) | m);
    h =
      ob(
        ((p >>> 0 > 3218235020) & m) | o | ((n >>> 0 > 3493216576) & m) | 0,
        0,
        h | 0,
        0
      ) | 0;
    n = ob(aa(h, 801750719) | 0, 0, n | 0, 0) | 0;
    m = E;
    c[a >> 2] = n;
    a = ob(aa(h, 1076732275) | 0, 0, c[k >> 2] | 0, 0) | 0;
    m = ob(a | 0, E | 0, m | 0, 0) | 0;
    a = E;
    c[k >> 2] = m;
    k = ob(aa(h, 1354194884) | 0, 0, c[l >> 2] | 0, 0) | 0;
    a = ob(k | 0, E | 0, a | 0, 0) | 0;
    k = E;
    c[l >> 2] = a;
    a = ob(aa(h, 1162945305) | 0, 0, c[j >> 2] | 0, 0) | 0;
    k = ob(a | 0, E | 0, k | 0, 0) | 0;
    a = E;
    c[j >> 2] = k;
    h = ob(h | 0, 0, c[g >> 2] | 0, 0) | 0;
    a = ob(h | 0, E | 0, a | 0, 0) | 0;
    c[g >> 2] = a;
    a = ob(E | 0, 0, c[f >> 2] | 0, 0) | 0;
    c[f >> 2] = a;
    a = ob(E | 0, 0, c[e >> 2] | 0, 0) | 0;
    c[e >> 2] = a;
    a = ob(E | 0, 0, c[b >> 2] | 0, 0) | 0;
    c[b >> 2] = a;
    i = d;
    return;
  }
  function Za(a, b, d) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0;
    e = i;
    n = ob(c[d >> 2] | 0, 0, c[b >> 2] | 0, 0) | 0;
    q = E;
    c[a >> 2] = n;
    n = ob(c[(d + 4) >> 2] | 0, 0, c[(b + 4) >> 2] | 0, 0) | 0;
    q = ob(n | 0, E | 0, q | 0, 0) | 0;
    n = E;
    k = (a + 4) | 0;
    c[k >> 2] = q;
    q = ob(c[(d + 8) >> 2] | 0, 0, c[(b + 8) >> 2] | 0, 0) | 0;
    n = ob(q | 0, E | 0, n | 0, 0) | 0;
    q = E;
    l = (a + 8) | 0;
    c[l >> 2] = n;
    o = ob(c[(d + 12) >> 2] | 0, 0, c[(b + 12) >> 2] | 0, 0) | 0;
    q = ob(o | 0, E | 0, q | 0, 0) | 0;
    o = E;
    j = (a + 12) | 0;
    c[j >> 2] = q;
    r = ob(c[(d + 16) >> 2] | 0, 0, c[(b + 16) >> 2] | 0, 0) | 0;
    o = ob(r | 0, E | 0, o | 0, 0) | 0;
    r = E;
    h = (a + 16) | 0;
    c[h >> 2] = o;
    p = ob(c[(d + 20) >> 2] | 0, 0, c[(b + 20) >> 2] | 0, 0) | 0;
    r = ob(p | 0, E | 0, r | 0, 0) | 0;
    p = E;
    g = (a + 20) | 0;
    c[g >> 2] = r;
    s = ob(c[(d + 24) >> 2] | 0, 0, c[(b + 24) >> 2] | 0, 0) | 0;
    p = ob(s | 0, E | 0, p | 0, 0) | 0;
    s = E;
    f = (a + 24) | 0;
    c[f >> 2] = p;
    m = ob(c[(d + 28) >> 2] | 0, 0, c[(b + 28) >> 2] | 0, 0) | 0;
    m = ob(m | 0, E | 0, s | 0, 0) | 0;
    b = E;
    d = (a + 28) | 0;
    c[d >> 2] = m;
    p = (o >>> 0 < 4294967294) | ((r | 0) != -1) | (((m & p) | 0) != -1);
    o = ((o | 0) == -1) & 1;
    m = ((p | (o ^ 1)) & (q >>> 0 < 3132021990)) | p;
    p = ((q >>> 0 > 3132021990) & ~m) | (o & ~p);
    m = ((n >>> 0 < 2940772411) & ~p) | m;
    p = ((n >>> 0 > 2940772411) & ~m) | p;
    n = c[k >> 2] | 0;
    m = ~(((n >>> 0 < 3218235020) & ~p) | m);
    o = c[a >> 2] | 0;
    b =
      ob(
        ((n >>> 0 > 3218235020) & m) | p | ((o >>> 0 > 3493216576) & m) | 0,
        0,
        b | 0,
        0
      ) | 0;
    o = ob(aa(b, 801750719) | 0, 0, o | 0, 0) | 0;
    m = E;
    c[a >> 2] = o;
    a = ob(aa(b, 1076732275) | 0, 0, n | 0, 0) | 0;
    m = ob(a | 0, E | 0, m | 0, 0) | 0;
    a = E;
    c[k >> 2] = m;
    k = ob(aa(b, 1354194884) | 0, 0, c[l >> 2] | 0, 0) | 0;
    a = ob(k | 0, E | 0, a | 0, 0) | 0;
    k = E;
    c[l >> 2] = a;
    a = ob(aa(b, 1162945305) | 0, 0, c[j >> 2] | 0, 0) | 0;
    k = ob(a | 0, E | 0, k | 0, 0) | 0;
    a = E;
    c[j >> 2] = k;
    b = ob(b | 0, 0, c[h >> 2] | 0, 0) | 0;
    a = ob(b | 0, E | 0, a | 0, 0) | 0;
    c[h >> 2] = a;
    a = ob(E | 0, 0, c[g >> 2] | 0, 0) | 0;
    c[g >> 2] = a;
    a = ob(E | 0, 0, c[f >> 2] | 0, 0) | 0;
    c[f >> 2] = a;
    a = ob(E | 0, 0, c[d >> 2] | 0, 0) | 0;
    c[d >> 2] = a;
    i = e;
    return;
  }
  function _a(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0;
    t = i;
    i = (i + 480) | 0;
    n = (t + 40) | 0;
    r = (t + 160) | 0;
    e = (t + 360) | 0;
    f = t;
    d = (t + 320) | 0;
    o = (t + 400) | 0;
    s = (t + 440) | 0;
    l = (t + 240) | 0;
    k = (t + 200) | 0;
    p = (t + 80) | 0;
    q = (t + 120) | 0;
    m = (t + 280) | 0;
    Ua(n, b);
    Va(n, n, b);
    Ua(r, n);
    Va(r, r, b);
    g = (e + 0) | 0;
    h = (r + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    Ua(e, e);
    Ua(e, e);
    Ua(e, e);
    Va(e, e, r);
    g = (f + 0) | 0;
    h = (e + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    Ua(f, f);
    Ua(f, f);
    Ua(f, f);
    Va(f, f, r);
    g = (d + 0) | 0;
    h = (f + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    Ua(d, d);
    Ua(d, d);
    Va(d, d, n);
    g = (o + 0) | 0;
    h = (d + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Ua(o, o);
    Va(o, o, d);
    g = (s + 0) | 0;
    h = (o + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Ua(s, s);
    Va(s, s, o);
    g = (l + 0) | 0;
    h = (s + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    d = 0;
    do {
      Ua(l, l);
      d = (d + 1) | 0;
    } while ((d | 0) != 44);
    Va(l, l, s);
    g = (k + 0) | 0;
    h = (l + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    d = 0;
    do {
      Ua(k, k);
      d = (d + 1) | 0;
    } while ((d | 0) != 88);
    Va(k, k, l);
    g = (p + 0) | 0;
    h = (k + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    d = 0;
    do {
      Ua(p, p);
      d = (d + 1) | 0;
    } while ((d | 0) != 44);
    Va(p, p, s);
    g = (q + 0) | 0;
    h = (p + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    Ua(q, q);
    Ua(q, q);
    Ua(q, q);
    Va(q, q, r);
    g = (m + 0) | 0;
    h = (q + 0) | 0;
    j = (g + 40) | 0;
    do {
      c[g >> 2] = c[h >> 2];
      g = (g + 4) | 0;
      h = (h + 4) | 0;
    } while ((g | 0) < (j | 0));
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Va(m, m, o);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Va(m, m, b);
    Ua(m, m);
    Ua(m, m);
    Ua(m, m);
    Va(m, m, n);
    Ua(m, m);
    Ua(m, m);
    Va(a, b, m);
    i = t;
    return;
  }
  function $a(a) {
    a = a | 0;
    var b = 0,
      d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      i = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0;
    z = (a + 4) | 0;
    w = (a + 8) | 0;
    t = (a + 12) | 0;
    q = (a + 16) | 0;
    n = (a + 20) | 0;
    k = (a + 24) | 0;
    h = (a + 28) | 0;
    g = (a + 32) | 0;
    b = (a + 36) | 0;
    d = c[b >> 2] | 0;
    y = d >>> 22;
    B = (((y * 977) | 0) + (c[a >> 2] | 0)) | 0;
    y = ((y << 6) + (c[z >> 2] | 0) + (B >>> 26)) | 0;
    A = B & 67108863;
    x = ((y >>> 26) + (c[w >> 2] | 0)) | 0;
    y = y & 67108863;
    u = ((x >>> 26) + (c[t >> 2] | 0)) | 0;
    r = ((u >>> 26) + (c[q >> 2] | 0)) | 0;
    o = ((r >>> 26) + (c[n >> 2] | 0)) | 0;
    l = ((o >>> 26) + (c[k >> 2] | 0)) | 0;
    i = ((l >>> 26) + (c[h >> 2] | 0)) | 0;
    j = l & 67108863;
    e = ((i >>> 26) + (c[g >> 2] | 0)) | 0;
    d = ((e >>> 26) + (d & 4194303)) | 0;
    v =
      (((d | 0) == 4194303
        ? ((u & x & r & o & j & i & e) | 0) == 67108863
        : 0) &
        (((y + 64 + (((A + 977) | 0) >>> 26)) | 0) >>> 0 > 67108863) &
        1) |
      (d >>> 22);
    C = (v * 977) | 0;
    A = ((v << 6) + y + (((C + A) | 0) >>> 26)) | 0;
    y = A >>> 26;
    v = ((y + (x & 67108863)) | 0) >>> 26;
    s = ((v + (u & 67108863)) | 0) >>> 26;
    p = ((s + (r & 67108863)) | 0) >>> 26;
    m = ((p + (o & 67108863)) | 0) >>> 26;
    j = ((m + j) | 0) >>> 26;
    f = ((j + (i & 67108863)) | 0) >>> 26;
    c[a >> 2] = (C + B) & 67108863;
    c[z >> 2] = A & 67108863;
    c[w >> 2] = (y + x) & 67108863;
    c[t >> 2] = (v + u) & 67108863;
    c[q >> 2] = (s + r) & 67108863;
    c[n >> 2] = (p + o) & 67108863;
    c[k >> 2] = (m + l) & 67108863;
    c[h >> 2] = (j + i) & 67108863;
    c[g >> 2] = (f + e) & 67108863;
    c[b >> 2] = ((((f + (e & 67108863)) | 0) >>> 26) + d) & 4194303;
    return;
  }
  function ab(a) {
    a = a | 0;
    var b = 0,
      d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0;
    G = i;
    b = (a + 4) | 0;
    l = (a + 8) | 0;
    x = (a + 12) | 0;
    E = (a + 16) | 0;
    F = (a + 20) | 0;
    d = (a + 24) | 0;
    e = (a + 28) | 0;
    f = (a + 32) | 0;
    g = (a + 36) | 0;
    A = c[g >> 2] | 0;
    m = A >>> 22;
    h = (((m * 977) | 0) + (c[a >> 2] | 0)) | 0;
    m = ((m << 6) + (c[b >> 2] | 0) + (h >>> 26)) | 0;
    j = h & 67108863;
    k = ((m >>> 26) + (c[l >> 2] | 0)) | 0;
    m = m & 67108863;
    n = ((k >>> 26) + (c[x >> 2] | 0)) | 0;
    o = k & 67108863;
    p = ((n >>> 26) + (c[E >> 2] | 0)) | 0;
    q = n & 67108863;
    r = ((p >>> 26) + (c[F >> 2] | 0)) | 0;
    s = p & 67108863;
    t = ((r >>> 26) + (c[d >> 2] | 0)) | 0;
    u = r & 67108863;
    v = ((t >>> 26) + (c[e >> 2] | 0)) | 0;
    w = t & 67108863;
    y = ((v >>> 26) + (c[f >> 2] | 0)) | 0;
    z = v & 67108863;
    A = ((y >>> 26) + (A & 4194303)) | 0;
    B = y & 67108863;
    C = ((j + 977) | 0) >>> 26;
    D =
      (((A | 0) == 4194303
        ? ((n & k & p & r & w & v & y) | 0) == 67108863
        : 0) &
        (((m + 64 + C) | 0) >>> 0 > 67108863) &
        1) |
      (A >>> 22);
    if (!D) {
      k = j;
      n = m;
      p = o;
      r = q;
      t = s;
      v = u;
      y = w;
      C = B;
      D = A;
      c[a >> 2] = k;
      c[b >> 2] = n;
      c[l >> 2] = p;
      c[x >> 2] = r;
      c[E >> 2] = t;
      c[F >> 2] = v;
      c[d >> 2] = y;
      c[e >> 2] = z;
      c[f >> 2] = C;
      c[g >> 2] = D;
      i = G;
      return;
    }
    m = (C + m + (D << 6)) | 0;
    L = m >>> 26;
    K = ((L + o) | 0) >>> 26;
    J = ((K + q) | 0) >>> 26;
    I = ((J + s) | 0) >>> 26;
    H = ((I + u) | 0) >>> 26;
    C = ((H + w) | 0) >>> 26;
    D = ((C + z) | 0) >>> 26;
    j = (h + 977) & 67108863;
    m = m & 67108863;
    o = (L + k) & 67108863;
    q = (K + n) & 67108863;
    s = (J + p) & 67108863;
    u = (I + r) & 67108863;
    w = (H + t) & 67108863;
    z = (C + v) & 67108863;
    C = (D + y) & 67108863;
    D = ((((D + B) | 0) >>> 26) + A) & 4194303;
    c[a >> 2] = j;
    c[b >> 2] = m;
    c[l >> 2] = o;
    c[x >> 2] = q;
    c[E >> 2] = s;
    c[F >> 2] = u;
    c[d >> 2] = w;
    c[e >> 2] = z;
    c[f >> 2] = C;
    c[g >> 2] = D;
    i = G;
    return;
  }
  function bb(a, b) {
    a = a | 0;
    b = b | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0;
    q = i;
    g = (a + 16) | 0;
    h = (a + 12) | 0;
    j = (a + 8) | 0;
    k = (a + 4) | 0;
    l = (a + 36) | 0;
    m = (a + 32) | 0;
    n = (a + 28) | 0;
    o = (a + 24) | 0;
    p = (a + 20) | 0;
    e = (a + 0) | 0;
    f = (e + 40) | 0;
    do {
      c[e >> 2] = 0;
      e = (e + 4) | 0;
    } while ((e | 0) < (f | 0));
    e = 0;
    do {
      r = e << 3;
      s = (b + (31 - e)) | 0;
      f = (a + ((((r | 0) / 26) | 0) << 2)) | 0;
      c[f >> 2] = (((d[s >> 0] | 0) & 3) << ((r | 0) % 26 | 0)) | c[f >> 2];
      f = r | 2;
      t = (a + ((((f | 0) / 26) | 0) << 2)) | 0;
      c[t >> 2] =
        ((((d[s >> 0] | 0) >>> 2) & 3) << ((f | 0) % 26 | 0)) | c[t >> 2];
      t = r | 4;
      f = (a + ((((t | 0) / 26) | 0) << 2)) | 0;
      c[f >> 2] =
        ((((d[s >> 0] | 0) >>> 4) & 3) << ((t | 0) % 26 | 0)) | c[f >> 2];
      r = r | 6;
      f = (a + ((((r | 0) / 26) | 0) << 2)) | 0;
      c[f >> 2] = (((d[s >> 0] | 0) >>> 6) << ((r | 0) % 26 | 0)) | c[f >> 2];
      e = (e + 1) | 0;
    } while ((e | 0) != 32);
    if (
      (
        (c[l >> 2] | 0) == 4194303
          ? ((c[n >> 2] &
              c[m >> 2] &
              c[o >> 2] &
              c[p >> 2] &
              c[g >> 2] &
              c[h >> 2] &
              c[j >> 2]) |
              0) ==
            67108863
          : 0
      )
        ? (((c[k >> 2] | 0) + 64 + ((((c[a >> 2] | 0) + 977) | 0) >>> 26)) |
            0) >>>
            0 >
          67108863
        : 0
    ) {
      t = 0;
      i = q;
      return t | 0;
    }
    t = 1;
    i = q;
    return t | 0;
  }
  function cb(a, b, d) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0;
    H = i;
    i = (i + 640) | 0;
    z = (H + 80) | 0;
    B = (H + 240) | 0;
    F = (H + 440) | 0;
    h = (H + 520) | 0;
    j = (H + 320) | 0;
    f = (H + 400) | 0;
    C = (H + 480) | 0;
    G = (H + 560) | 0;
    x = (H + 600) | 0;
    w = (H + 40) | 0;
    D = (H + 280) | 0;
    E = (H + 120) | 0;
    A = H;
    e = (H + 160) | 0;
    g = (H + 360) | 0;
    y = (H + 200) | 0;
    k = (a + 0) | 0;
    l = (b + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(e, b);
    Va(g, b, e);
    c[(a + 80) >> 2] = 0;
    n = (y + 4) | 0;
    c[(n + 0) >> 2] = 0;
    c[(n + 4) >> 2] = 0;
    c[(n + 8) >> 2] = 0;
    c[(n + 12) >> 2] = 0;
    c[(n + 16) >> 2] = 0;
    c[(n + 20) >> 2] = 0;
    c[(n + 24) >> 2] = 0;
    c[(n + 28) >> 2] = 0;
    c[y >> 2] = (c[g >> 2] | 0) + 7;
    c[n >> 2] = c[(g + 4) >> 2];
    v = (y + 8) | 0;
    c[v >> 2] = c[(g + 8) >> 2];
    o = (y + 12) | 0;
    c[o >> 2] = c[(g + 12) >> 2];
    p = (y + 16) | 0;
    c[p >> 2] = c[(g + 16) >> 2];
    q = c[(g + 20) >> 2] | 0;
    c[(y + 20) >> 2] = q;
    r = (y + 24) | 0;
    c[r >> 2] = c[(g + 24) >> 2];
    s = (y + 28) | 0;
    c[s >> 2] = c[(g + 28) >> 2];
    t = (y + 32) | 0;
    c[t >> 2] = c[(g + 32) >> 2];
    u = (y + 36) | 0;
    c[u >> 2] = c[(g + 36) >> 2];
    Ua(B, y);
    Va(B, B, y);
    Ua(F, B);
    Va(F, F, y);
    k = (h + 0) | 0;
    l = (F + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(h, h);
    Ua(h, h);
    Ua(h, h);
    Va(h, h, F);
    k = (j + 0) | 0;
    l = (h + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(j, j);
    Ua(j, j);
    Ua(j, j);
    Va(j, j, F);
    k = (f + 0) | 0;
    l = (j + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(f, f);
    Ua(f, f);
    Va(f, f, B);
    k = (C + 0) | 0;
    l = (f + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Ua(C, C);
    Va(C, C, f);
    k = (G + 0) | 0;
    l = (C + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Ua(G, G);
    Va(G, G, C);
    k = (x + 0) | 0;
    l = (G + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    e = 0;
    do {
      Ua(x, x);
      e = (e + 1) | 0;
    } while ((e | 0) != 44);
    f = (a + 40) | 0;
    Va(x, x, G);
    k = (w + 0) | 0;
    l = (x + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    e = 0;
    do {
      Ua(w, w);
      e = (e + 1) | 0;
    } while ((e | 0) != 88);
    Va(w, w, x);
    k = (D + 0) | 0;
    l = (w + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    b = 0;
    do {
      Ua(D, D);
      b = (b + 1) | 0;
    } while ((b | 0) != 44);
    Va(D, D, G);
    k = (E + 0) | 0;
    l = (D + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(E, E);
    Ua(E, E);
    Ua(E, E);
    Va(E, E, F);
    k = (A + 0) | 0;
    l = (E + 0) | 0;
    m = (k + 40) | 0;
    do {
      c[k >> 2] = c[l >> 2];
      k = (k + 4) | 0;
      l = (l + 4) | 0;
    } while ((k | 0) < (m | 0));
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Va(A, A, C);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Ua(A, A);
    Va(A, A, B);
    Ua(A, A);
    Ua(f, A);
    Ua(A, f);
    m = (268435196 - (c[(A + 4) >> 2] | 0)) | 0;
    w = (268435452 - (c[(A + 8) >> 2] | 0)) | 0;
    x = (268435452 - (c[(A + 12) >> 2] | 0)) | 0;
    B = (268435452 - (c[(A + 16) >> 2] | 0)) | 0;
    C = (268435452 - (c[(A + 20) >> 2] | 0)) | 0;
    D = (268435452 - (c[(A + 24) >> 2] | 0)) | 0;
    E = (268435452 - (c[(A + 28) >> 2] | 0)) | 0;
    F = (268435452 - (c[(A + 32) >> 2] | 0)) | 0;
    G = (16777212 - (c[(A + 36) >> 2] | 0)) | 0;
    c[z >> 2] = 268431548 - (c[A >> 2] | 0) + (c[y >> 2] | 0);
    c[(z + 4) >> 2] = m + (c[n >> 2] | 0);
    c[(z + 8) >> 2] = w + (c[v >> 2] | 0);
    c[(z + 12) >> 2] = x + (c[o >> 2] | 0);
    c[(z + 16) >> 2] = B + (c[p >> 2] | 0);
    c[(z + 20) >> 2] = C + q;
    c[(z + 24) >> 2] = D + (c[r >> 2] | 0);
    c[(z + 28) >> 2] = E + (c[s >> 2] | 0);
    c[(z + 32) >> 2] = F + (c[t >> 2] | 0);
    c[(z + 36) >> 2] = G + (c[u >> 2] | 0);
    if (!(Wa(z) | 0)) {
      a = 0;
      i = H;
      return a | 0;
    }
    ab(f);
    b = c[f >> 2] | 0;
    if (((b & 1) | 0) == (d | 0)) {
      a = 1;
      i = H;
      return a | 0;
    }
    c[f >> 2] = 268431548 - b;
    d = (a + 44) | 0;
    c[d >> 2] = 268435196 - (c[d >> 2] | 0);
    d = (a + 48) | 0;
    c[d >> 2] = 268435452 - (c[d >> 2] | 0);
    d = (a + 52) | 0;
    c[d >> 2] = 268435452 - (c[d >> 2] | 0);
    d = (a + 56) | 0;
    c[d >> 2] = 268435452 - (c[d >> 2] | 0);
    d = (a + 60) | 0;
    c[d >> 2] = 268435452 - (c[d >> 2] | 0);
    d = (a + 64) | 0;
    c[d >> 2] = 268435452 - (c[d >> 2] | 0);
    d = (a + 68) | 0;
    c[d >> 2] = 268435452 - (c[d >> 2] | 0);
    d = (a + 72) | 0;
    c[d >> 2] = 268435452 - (c[d >> 2] | 0);
    a = (a + 76) | 0;
    c[a >> 2] = 16777212 - (c[a >> 2] | 0);
    a = 1;
    i = H;
    return a | 0;
  }
  function db(a, b) {
    a = a | 0;
    b = b | 0;
    var c = 0,
      d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0;
    o = i;
    i = (i + 352) | 0;
    g = (o + 288) | 0;
    h = (o + 128) | 0;
    j = o;
    k = (o + 224) | 0;
    m = (o + 256) | 0;
    n = (o + 320) | 0;
    c = (o + 96) | 0;
    d = (o + 192) | 0;
    l = (o + 160) | 0;
    e = (o + 64) | 0;
    f = (o + 32) | 0;
    eb(g, b);
    Xa(g, g, b);
    eb(h, g);
    Xa(h, h, b);
    eb(j, h);
    Xa(j, j, b);
    eb(k, j);
    eb(k, k);
    Xa(k, k, g);
    eb(m, k);
    Xa(m, m, b);
    eb(n, m);
    Xa(n, n, b);
    eb(c, n);
    eb(c, c);
    eb(c, c);
    eb(c, c);
    eb(c, c);
    eb(c, c);
    eb(c, c);
    Xa(c, c, m);
    eb(d, c);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    eb(d, d);
    Xa(d, d, c);
    eb(l, d);
    c = 0;
    do {
      eb(l, l);
      c = (c + 1) | 0;
    } while ((c | 0) != 29);
    Xa(l, l, d);
    eb(e, l);
    c = 0;
    do {
      eb(e, e);
      c = (c + 1) | 0;
    } while ((c | 0) != 59);
    Xa(e, e, l);
    eb(f, e);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, m);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, h);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, h);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, g);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, h);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, h);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, g);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, j);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, h);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, h);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, n);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, j);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, g);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, g);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, g);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, g);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(f, f, b);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    eb(f, f);
    Xa(a, f, k);
    i = o;
    return;
  }
  function eb(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0,
      N = 0;
    d = i;
    i = (i + 64) | 0;
    e = d;
    K = c[b >> 2] | 0;
    o = Bb(K | 0, 0, K | 0, 0) | 0;
    j = E;
    c[e >> 2] = o;
    o = (b + 4) | 0;
    D = c[o >> 2] | 0;
    t = Bb(D | 0, 0, K | 0, 0) | 0;
    B = E;
    x = rb(B | 0, 0, 1) | 0;
    A = t << 1;
    j = (A + j) | 0;
    q = j >>> 0 < A >>> 0;
    t = (((A >>> 0 < t >>> 0) | x) + (q & 1)) | 0;
    c[(e + 4) >> 2] = j;
    j = (b + 8) | 0;
    A = c[j >> 2] | 0;
    H = Bb(A | 0, 0, K | 0, 0) | 0;
    l = E;
    m = rb(l | 0, 0, 1) | 0;
    J = H << 1;
    h = (t + J) | 0;
    F = h >>> 0 < J >>> 0;
    H = ((F & 1) + ((J >>> 0 < H >>> 0) | m)) | 0;
    B = ((q & ((t | 0) == 0) & 1) + ((x >>> 0 < B >>> 0) & 1) + H) | 0;
    x = Bb(D | 0, 0, D | 0, 0) | 0;
    h = (h + x) | 0;
    x = (((h >>> 0 < x >>> 0) & 1) + E) | 0;
    t = (B + x) | 0;
    c[(e + 8) >> 2] = h;
    h = (b + 12) | 0;
    q = c[h >> 2] | 0;
    K = Bb(q | 0, 0, K | 0, 0) | 0;
    J = E;
    z = rb(J | 0, 0, 1) | 0;
    w = K << 1;
    L = (t + w) | 0;
    M = L >>> 0 < w >>> 0;
    K = ((M & 1) + ((w >>> 0 < K >>> 0) | z)) | 0;
    x =
      ((F & ((H | 0) == 0) & 1) +
        ((m >>> 0 < l >>> 0) & 1) +
        ((B >>> 0 < H >>> 0) & 1) +
        ((t >>> 0 < x >>> 0) & 1) +
        K) |
      0;
    D = Bb(A | 0, 0, D | 0, 0) | 0;
    A = E;
    t = rb(A | 0, 0, 1) | 0;
    H = D << 1;
    L = (L + H) | 0;
    B = L >>> 0 < H >>> 0;
    D = ((B & 1) + ((H >>> 0 < D >>> 0) | t)) | 0;
    H = (x + D) | 0;
    c[(e + 12) >> 2] = L;
    L = c[b >> 2] | 0;
    l = (b + 16) | 0;
    m = c[l >> 2] | 0;
    F = Bb(m | 0, 0, L | 0, 0) | 0;
    w = E;
    s = rb(w | 0, 0, 1) | 0;
    G = F << 1;
    n = (H + G) | 0;
    C = n >>> 0 < G >>> 0;
    F = ((C & 1) + ((G >>> 0 < F >>> 0) | s)) | 0;
    D =
      (((t >>> 0 < A >>> 0) & 1) +
        ((z >>> 0 < J >>> 0) & 1) +
        (M & ((K | 0) == 0) & 1) +
        ((x >>> 0 < K >>> 0) & 1) +
        (B & ((D | 0) == 0) & 1) +
        ((H >>> 0 < D >>> 0) & 1) +
        F) |
      0;
    H = c[o >> 2] | 0;
    q = Bb(q | 0, 0, H | 0, 0) | 0;
    B = E;
    K = rb(B | 0, 0, 1) | 0;
    x = q << 1;
    n = (n + x) | 0;
    M = n >>> 0 < x >>> 0;
    q = ((M & 1) + ((x >>> 0 < q >>> 0) | K)) | 0;
    x = (D + q) | 0;
    J = c[j >> 2] | 0;
    z = Bb(J | 0, 0, J | 0, 0) | 0;
    n = (n + z) | 0;
    z = (((n >>> 0 < z >>> 0) & 1) + E) | 0;
    A = (x + z) | 0;
    c[(e + 16) >> 2] = n;
    n = (b + 20) | 0;
    L = Bb(c[n >> 2] | 0, 0, L | 0, 0) | 0;
    t = E;
    G = rb(t | 0, 0, 1) | 0;
    k = L << 1;
    g = (A + k) | 0;
    v = g >>> 0 < k >>> 0;
    L = ((v & 1) + ((k >>> 0 < L >>> 0) | G)) | 0;
    z =
      (((K >>> 0 < B >>> 0) & 1) +
        ((s >>> 0 < w >>> 0) & 1) +
        (C & ((F | 0) == 0) & 1) +
        ((D >>> 0 < F >>> 0) & 1) +
        (M & ((q | 0) == 0) & 1) +
        ((x >>> 0 < q >>> 0) & 1) +
        ((A >>> 0 < z >>> 0) & 1) +
        L) |
      0;
    H = Bb(m | 0, 0, H | 0, 0) | 0;
    m = E;
    A = rb(m | 0, 0, 1) | 0;
    q = H << 1;
    g = (g + q) | 0;
    x = g >>> 0 < q >>> 0;
    H = ((x & 1) + ((q >>> 0 < H >>> 0) | A)) | 0;
    q = (z + H) | 0;
    J = Bb(c[h >> 2] | 0, 0, J | 0, 0) | 0;
    M = E;
    F = rb(M | 0, 0, 1) | 0;
    D = J << 1;
    g = (g + D) | 0;
    C = g >>> 0 < D >>> 0;
    J = ((C & 1) + ((D >>> 0 < J >>> 0) | F)) | 0;
    D = (q + J) | 0;
    c[(e + 20) >> 2] = g;
    g = (b + 24) | 0;
    w = Bb(c[g >> 2] | 0, 0, c[b >> 2] | 0, 0) | 0;
    s = E;
    B = rb(s | 0, 0, 1) | 0;
    K = w << 1;
    k = (D + K) | 0;
    f = k >>> 0 < K >>> 0;
    w = ((f & 1) + ((K >>> 0 < w >>> 0) | B)) | 0;
    J =
      (((A >>> 0 < m >>> 0) & 1) +
        ((G >>> 0 < t >>> 0) & 1) +
        ((F >>> 0 < M >>> 0) & 1) +
        (v & ((L | 0) == 0) & 1) +
        ((z >>> 0 < L >>> 0) & 1) +
        (x & ((H | 0) == 0) & 1) +
        ((q >>> 0 < H >>> 0) & 1) +
        (C & ((J | 0) == 0) & 1) +
        ((D >>> 0 < J >>> 0) & 1) +
        w) |
      0;
    D = Bb(c[n >> 2] | 0, 0, c[o >> 2] | 0, 0) | 0;
    C = E;
    H = rb(C | 0, 0, 1) | 0;
    q = D << 1;
    k = (k + q) | 0;
    x = k >>> 0 < q >>> 0;
    D = ((x & 1) + ((q >>> 0 < D >>> 0) | H)) | 0;
    q = (J + D) | 0;
    L = Bb(c[l >> 2] | 0, 0, c[j >> 2] | 0, 0) | 0;
    z = E;
    v = rb(z | 0, 0, 1) | 0;
    M = L << 1;
    k = (k + M) | 0;
    F = k >>> 0 < M >>> 0;
    L = ((F & 1) + ((M >>> 0 < L >>> 0) | v)) | 0;
    M = (q + L) | 0;
    t = c[h >> 2] | 0;
    t = Bb(t | 0, 0, t | 0, 0) | 0;
    k = (k + t) | 0;
    t = (((k >>> 0 < t >>> 0) & 1) + E) | 0;
    G = (M + t) | 0;
    c[(e + 24) >> 2] = k;
    k = (b + 28) | 0;
    m = Bb(c[k >> 2] | 0, 0, c[b >> 2] | 0, 0) | 0;
    A = E;
    K = rb(A | 0, 0, 1) | 0;
    I = m << 1;
    p = (G + I) | 0;
    u = p >>> 0 < I >>> 0;
    m = ((u & 1) + ((I >>> 0 < m >>> 0) | K)) | 0;
    t =
      (((H >>> 0 < C >>> 0) & 1) +
        ((B >>> 0 < s >>> 0) & 1) +
        ((v >>> 0 < z >>> 0) & 1) +
        (f & ((w | 0) == 0) & 1) +
        (x & ((D | 0) == 0) & 1) +
        ((J >>> 0 < w >>> 0) & 1) +
        (F & ((L | 0) == 0) & 1) +
        ((q >>> 0 < D >>> 0) & 1) +
        ((M >>> 0 < L >>> 0) & 1) +
        ((G >>> 0 < t >>> 0) & 1) +
        m) |
      0;
    o = c[o >> 2] | 0;
    G = Bb(c[g >> 2] | 0, 0, o | 0, 0) | 0;
    L = E;
    M = rb(L | 0, 0, 1) | 0;
    D = G << 1;
    p = (p + D) | 0;
    q = p >>> 0 < D >>> 0;
    G = ((q & 1) + ((D >>> 0 < G >>> 0) | M)) | 0;
    D = (t + G) | 0;
    F = c[j >> 2] | 0;
    w = Bb(c[n >> 2] | 0, 0, F | 0, 0) | 0;
    J = E;
    x = rb(J | 0, 0, 1) | 0;
    f = w << 1;
    p = (p + f) | 0;
    z = p >>> 0 < f >>> 0;
    w = ((z & 1) + ((f >>> 0 < w >>> 0) | x)) | 0;
    f = (D + w) | 0;
    v = c[h >> 2] | 0;
    s = Bb(c[l >> 2] | 0, 0, v | 0, 0) | 0;
    B = E;
    C = rb(B | 0, 0, 1) | 0;
    H = s << 1;
    p = (p + H) | 0;
    I = p >>> 0 < H >>> 0;
    s = ((I & 1) + ((H >>> 0 < s >>> 0) | C)) | 0;
    H = (f + s) | 0;
    c[(e + 28) >> 2] = p;
    o = Bb(c[k >> 2] | 0, 0, o | 0, 0) | 0;
    p = E;
    b = rb(p | 0, 0, 1) | 0;
    N = o << 1;
    r = (H + N) | 0;
    y = r >>> 0 < N >>> 0;
    o = ((y & 1) + ((N >>> 0 < o >>> 0) | b)) | 0;
    s =
      (((M >>> 0 < L >>> 0) & 1) +
        ((K >>> 0 < A >>> 0) & 1) +
        ((x >>> 0 < J >>> 0) & 1) +
        ((C >>> 0 < B >>> 0) & 1) +
        (u & ((m | 0) == 0) & 1) +
        ((t >>> 0 < m >>> 0) & 1) +
        (q & ((G | 0) == 0) & 1) +
        ((D >>> 0 < G >>> 0) & 1) +
        (z & ((w | 0) == 0) & 1) +
        ((f >>> 0 < w >>> 0) & 1) +
        (I & ((s | 0) == 0) & 1) +
        ((H >>> 0 < s >>> 0) & 1) +
        o) |
      0;
    F = Bb(c[g >> 2] | 0, 0, F | 0, 0) | 0;
    H = E;
    I = rb(H | 0, 0, 1) | 0;
    w = F << 1;
    r = (r + w) | 0;
    f = r >>> 0 < w >>> 0;
    F = ((f & 1) + ((w >>> 0 < F >>> 0) | I)) | 0;
    w = (s + F) | 0;
    v = Bb(c[n >> 2] | 0, 0, v | 0, 0) | 0;
    z = E;
    G = rb(z | 0, 0, 1) | 0;
    D = v << 1;
    r = (r + D) | 0;
    q = r >>> 0 < D >>> 0;
    v = ((q & 1) + ((D >>> 0 < v >>> 0) | G)) | 0;
    D = (w + v) | 0;
    m = c[l >> 2] | 0;
    t = Bb(m | 0, 0, m | 0, 0) | 0;
    r = (r + t) | 0;
    t = (((r >>> 0 < t >>> 0) & 1) + E) | 0;
    u = (D + t) | 0;
    c[(e + 32) >> 2] = r;
    r = c[k >> 2] | 0;
    j = Bb(r | 0, 0, c[j >> 2] | 0, 0) | 0;
    B = E;
    C = rb(B | 0, 0, 1) | 0;
    J = j << 1;
    x = (u + J) | 0;
    A = x >>> 0 < J >>> 0;
    j = ((A & 1) + ((J >>> 0 < j >>> 0) | C)) | 0;
    t =
      (((I >>> 0 < H >>> 0) & 1) +
        ((b >>> 0 < p >>> 0) & 1) +
        ((G >>> 0 < z >>> 0) & 1) +
        (y & ((o | 0) == 0) & 1) +
        (f & ((F | 0) == 0) & 1) +
        (q & ((v | 0) == 0) & 1) +
        ((s >>> 0 < o >>> 0) & 1) +
        ((w >>> 0 < F >>> 0) & 1) +
        ((D >>> 0 < v >>> 0) & 1) +
        ((u >>> 0 < t >>> 0) & 1) +
        j) |
      0;
    h = c[h >> 2] | 0;
    u = c[g >> 2] | 0;
    v = Bb(u | 0, 0, h | 0, 0) | 0;
    D = E;
    F = rb(D | 0, 0, 1) | 0;
    w = v << 1;
    x = (x + w) | 0;
    o = x >>> 0 < w >>> 0;
    v = ((o & 1) + ((w >>> 0 < v >>> 0) | F)) | 0;
    w = (t + v) | 0;
    s = c[n >> 2] | 0;
    m = Bb(s | 0, 0, m | 0, 0) | 0;
    q = E;
    f = rb(q | 0, 0, 1) | 0;
    y = m << 1;
    x = (x + y) | 0;
    z = x >>> 0 < y >>> 0;
    m = ((z & 1) + ((y >>> 0 < m >>> 0) | f)) | 0;
    y = (w + m) | 0;
    c[(e + 36) >> 2] = x;
    h = Bb(r | 0, 0, h | 0, 0) | 0;
    r = E;
    x = rb(r | 0, 0, 1) | 0;
    G = h << 1;
    p = (y + G) | 0;
    b = p >>> 0 < G >>> 0;
    h = ((b & 1) + ((G >>> 0 < h >>> 0) | x)) | 0;
    m =
      (((F >>> 0 < D >>> 0) & 1) +
        ((C >>> 0 < B >>> 0) & 1) +
        ((f >>> 0 < q >>> 0) & 1) +
        (A & ((j | 0) == 0) & 1) +
        ((t >>> 0 < j >>> 0) & 1) +
        (o & ((v | 0) == 0) & 1) +
        ((w >>> 0 < v >>> 0) & 1) +
        (z & ((m | 0) == 0) & 1) +
        ((y >>> 0 < m >>> 0) & 1) +
        h) |
      0;
    l = c[l >> 2] | 0;
    u = Bb(u | 0, 0, l | 0, 0) | 0;
    y = E;
    z = rb(y | 0, 0, 1) | 0;
    v = u << 1;
    p = (p + v) | 0;
    w = p >>> 0 < v >>> 0;
    u = ((w & 1) + ((v >>> 0 < u >>> 0) | z)) | 0;
    v = (m + u) | 0;
    s = Bb(s | 0, 0, s | 0, 0) | 0;
    p = (p + s) | 0;
    s = (((p >>> 0 < s >>> 0) & 1) + E) | 0;
    o = (v + s) | 0;
    c[(e + 40) >> 2] = p;
    p = c[k >> 2] | 0;
    l = Bb(p | 0, 0, l | 0, 0) | 0;
    j = E;
    t = rb(j | 0, 0, 1) | 0;
    A = l << 1;
    q = (o + A) | 0;
    f = q >>> 0 < A >>> 0;
    l = ((f & 1) + ((A >>> 0 < l >>> 0) | t)) | 0;
    s =
      (((z >>> 0 < y >>> 0) & 1) +
        ((x >>> 0 < r >>> 0) & 1) +
        (b & ((h | 0) == 0) & 1) +
        (w & ((u | 0) == 0) & 1) +
        ((m >>> 0 < h >>> 0) & 1) +
        ((v >>> 0 < u >>> 0) & 1) +
        ((o >>> 0 < s >>> 0) & 1) +
        l) |
      0;
    n = c[n >> 2] | 0;
    g = c[g >> 2] | 0;
    o = Bb(g | 0, 0, n | 0, 0) | 0;
    u = E;
    v = rb(u | 0, 0, 1) | 0;
    h = o << 1;
    q = (q + h) | 0;
    m = q >>> 0 < h >>> 0;
    o = ((m & 1) + ((h >>> 0 < o >>> 0) | v)) | 0;
    h = (s + o) | 0;
    c[(e + 44) >> 2] = q;
    n = Bb(p | 0, 0, n | 0, 0) | 0;
    p = E;
    q = rb(p | 0, 0, 1) | 0;
    w = n << 1;
    b = (h + w) | 0;
    r = b >>> 0 < w >>> 0;
    n = ((r & 1) + ((w >>> 0 < n >>> 0) | q)) | 0;
    o =
      (((v >>> 0 < u >>> 0) & 1) +
        ((t >>> 0 < j >>> 0) & 1) +
        (f & ((l | 0) == 0) & 1) +
        ((s >>> 0 < l >>> 0) & 1) +
        (m & ((o | 0) == 0) & 1) +
        ((h >>> 0 < o >>> 0) & 1) +
        n) |
      0;
    h = Bb(g | 0, 0, g | 0, 0) | 0;
    b = (b + h) | 0;
    h = (((b >>> 0 < h >>> 0) & 1) + E) | 0;
    m = (o + h) | 0;
    c[(e + 48) >> 2] = b;
    b = c[k >> 2] | 0;
    g = Bb(b | 0, 0, g | 0, 0) | 0;
    k = E;
    l = rb(k | 0, 0, 1) | 0;
    s = g << 1;
    f = (m + s) | 0;
    j = f >>> 0 < s >>> 0;
    g = ((j & 1) + ((s >>> 0 < g >>> 0) | l)) | 0;
    h =
      ((r & ((n | 0) == 0) & 1) +
        ((q >>> 0 < p >>> 0) & 1) +
        ((o >>> 0 < n >>> 0) & 1) +
        ((m >>> 0 < h >>> 0) & 1) +
        g) |
      0;
    c[(e + 52) >> 2] = f;
    b = Bb(b | 0, 0, b | 0, 0) | 0;
    f = (h + b) | 0;
    c[(e + 56) >> 2] = f;
    c[(e + 60) >> 2] =
      ((l >>> 0 < k >>> 0) & 1) +
      E +
      (j & ((g | 0) == 0) & 1) +
      ((h >>> 0 < g >>> 0) & 1) +
      ((f >>> 0 < b >>> 0) & 1);
    Ya(a, e);
    i = d;
    return;
  }
  function fb(b, e) {
    b = b | 0;
    e = e | 0;
    var f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0;
    m = i;
    i = (i + 64) | 0;
    l = m;
    g = (l + 0) | 0;
    e = (e + 0) | 0;
    f = (g + 32) | 0;
    do {
      a[g >> 0] = a[e >> 0] | 0;
      g = (g + 1) | 0;
      e = (e + 1) | 0;
    } while ((g | 0) < (f | 0));
    g = (l + 32) | 0;
    f = (g + 32) | 0;
    do {
      a[g >> 0] = 0;
      g = (g + 1) | 0;
    } while ((g | 0) < (f | 0));
    h = (b + 196) | 0;
    c[h >> 2] = 1779033703;
    c[(b + 200) >> 2] = -1150833019;
    c[(b + 204) >> 2] = 1013904242;
    c[(b + 208) >> 2] = -1521486534;
    c[(b + 212) >> 2] = 1359893119;
    c[(b + 216) >> 2] = -1694144372;
    c[(b + 220) >> 2] = 528734635;
    c[(b + 224) >> 2] = 1541459225;
    j = (b + 388) | 0;
    c[j >> 2] = 0;
    e = 0;
    do {
      k = (l + e) | 0;
      a[k >> 0] = (d[k >> 0] | 0) ^ 92;
      e = (e + 1) | 0;
    } while ((e | 0) != 64);
    k = (l + 64) | 0;
    g = (l + 64) | 0;
    f = l;
    e = g;
    while (1) {
      ib(h, f);
      c[j >> 2] = (c[j >> 2] | 0) + 64;
      f = (e + 64) | 0;
      if (k >>> 0 < f >>> 0) break;
      else {
        n = e;
        e = f;
        f = n;
      }
    }
    if (k >>> 0 > e >>> 0) {
      n = (k - e) | 0;
      tb((b + 324) | 0, e | 0, n | 0) | 0;
      c[j >> 2] = (c[j >> 2] | 0) + n;
    }
    c[b >> 2] = 1779033703;
    c[(b + 4) >> 2] = -1150833019;
    c[(b + 8) >> 2] = 1013904242;
    c[(b + 12) >> 2] = -1521486534;
    c[(b + 16) >> 2] = 1359893119;
    c[(b + 20) >> 2] = -1694144372;
    c[(b + 24) >> 2] = 528734635;
    c[(b + 28) >> 2] = 1541459225;
    h = (b + 192) | 0;
    c[h >> 2] = 0;
    f = 0;
    do {
      n = (l + f) | 0;
      a[n >> 0] = (d[n >> 0] | 0) ^ 106;
      f = (f + 1) | 0;
    } while ((f | 0) != 64);
    f = l;
    while (1) {
      ib(b, f);
      c[h >> 2] = (c[h >> 2] | 0) + 64;
      e = (g + 64) | 0;
      if (k >>> 0 < e >>> 0) break;
      else {
        f = g;
        g = e;
      }
    }
    if (k >>> 0 <= g >>> 0) {
      i = m;
      return;
    }
    n = (k - g) | 0;
    tb((b + 128) | 0, g | 0, n | 0) | 0;
    c[h >> 2] = (c[h >> 2] | 0) + n;
    i = m;
    return;
  }
  function gb(b, d) {
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0;
    m = i;
    i = (i + 32) | 0;
    k = m;
    hb(b, k);
    l = (b + 196) | 0;
    h = (k + 32) | 0;
    j = (b + 388) | 0;
    f = c[j >> 2] & 63;
    if (((f | 0) != 0) & (((f + 32) | 0) >>> 0 > 63)) {
      e = (64 - f) | 0;
      tb((b + f + 324) | 0, k | 0, e | 0) | 0;
      c[j >> 2] = (c[j >> 2] | 0) + e;
      ib(l, (b + 324) | 0);
      e = (k + e) | 0;
      g = 0;
    } else {
      e = k;
      g = f;
    }
    f = (e + 64) | 0;
    if (h >>> 0 < f >>> 0) f = e;
    else
      while (1) {
        ib(l, e);
        c[j >> 2] = (c[j >> 2] | 0) + 64;
        e = (f + 64) | 0;
        if (h >>> 0 < e >>> 0) break;
        else {
          n = f;
          f = e;
          e = n;
        }
      }
    if (h >>> 0 <= f >>> 0) {
      e = (k + 0) | 0;
      f = (e + 32) | 0;
      do {
        a[e >> 0] = 0;
        e = (e + 1) | 0;
      } while ((e | 0) < (f | 0));
      hb(l, d);
      i = m;
      return;
    }
    e = (h - f) | 0;
    tb((b + g + 324) | 0, f | 0, e | 0) | 0;
    c[j >> 2] = (c[j >> 2] | 0) + e;
    e = (k + 0) | 0;
    f = (e + 32) | 0;
    do {
      a[e >> 0] = 0;
      e = (e + 1) | 0;
    } while ((e | 0) < (f | 0));
    hb(l, d);
    i = m;
    return;
  }
  function hb(b, d) {
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0;
    l = i;
    i = (i + 16) | 0;
    f = l;
    k = (b + 192) | 0;
    a[f >> 0] = 0;
    a[(f + 1) >> 0] = 0;
    a[(f + 2) >> 0] = 0;
    e = c[k >> 2] | 0;
    a[(f + 3) >> 0] = e >>> 29;
    a[(f + 4) >> 0] = e >>> 21;
    a[(f + 5) >> 0] = e >>> 13;
    a[(f + 6) >> 0] = e >>> 5;
    a[(f + 7) >> 0] = e << 3;
    h = (((119 - e) & 63) + 1) | 0;
    j = (392 + h) | 0;
    e = e & 63;
    if (((e | 0) != 0) & (((h + e) | 0) >>> 0 > 63)) {
      g = (64 - e) | 0;
      tb((b + e + 128) | 0, 392, g | 0) | 0;
      c[k >> 2] = (c[k >> 2] | 0) + g;
      ib(b, (b + 128) | 0);
      g = (392 + g) | 0;
      h = 0;
    } else {
      g = 392;
      h = e;
    }
    e = (g + 64) | 0;
    if (j >>> 0 < e >>> 0) e = g;
    else
      while (1) {
        ib(b, g);
        c[k >> 2] = (c[k >> 2] | 0) + 64;
        g = (e + 64) | 0;
        if (j >>> 0 < g >>> 0) break;
        else {
          m = e;
          e = g;
          g = m;
        }
      }
    if (j >>> 0 > e >>> 0) {
      m = (j - e) | 0;
      tb((b + h + 128) | 0, e | 0, m | 0) | 0;
      e = ((c[k >> 2] | 0) + m) | 0;
      c[k >> 2] = e;
    } else e = c[k >> 2] | 0;
    j = (f + 8) | 0;
    e = e & 63;
    if (((e | 0) != 0) & (((e + 8) | 0) >>> 0 > 63)) {
      g = (64 - e) | 0;
      tb((b + e + 128) | 0, f | 0, g | 0) | 0;
      c[k >> 2] = (c[k >> 2] | 0) + g;
      ib(b, (b + 128) | 0);
      f = (f + g) | 0;
      g = 0;
    } else g = e;
    e = (f + 64) | 0;
    if (j >>> 0 < e >>> 0) e = f;
    else
      while (1) {
        ib(b, f);
        c[k >> 2] = (c[k >> 2] | 0) + 64;
        f = (e + 64) | 0;
        if (j >>> 0 < f >>> 0) break;
        else {
          m = e;
          e = f;
          f = m;
        }
      }
    if (j >>> 0 > e >>> 0) {
      m = (j - e) | 0;
      tb((b + g + 128) | 0, e | 0, m | 0) | 0;
      c[k >> 2] = (c[k >> 2] | 0) + m;
    }
    a[d >> 0] = (c[b >> 2] | 0) >>> 24;
    a[(d + 1) >> 0] = (c[b >> 2] | 0) >>> 16;
    a[(d + 2) >> 0] = (c[b >> 2] | 0) >>> 8;
    a[(d + 3) >> 0] = c[b >> 2];
    c[b >> 2] = 0;
    m = (b + 4) | 0;
    a[(d + 4) >> 0] = (c[m >> 2] | 0) >>> 24;
    a[(d + 5) >> 0] = (c[m >> 2] | 0) >>> 16;
    a[(d + 6) >> 0] = (c[m >> 2] | 0) >>> 8;
    a[(d + 7) >> 0] = c[m >> 2];
    c[m >> 2] = 0;
    m = (b + 8) | 0;
    a[(d + 8) >> 0] = (c[m >> 2] | 0) >>> 24;
    a[(d + 9) >> 0] = (c[m >> 2] | 0) >>> 16;
    a[(d + 10) >> 0] = (c[m >> 2] | 0) >>> 8;
    a[(d + 11) >> 0] = c[m >> 2];
    c[m >> 2] = 0;
    m = (b + 12) | 0;
    a[(d + 12) >> 0] = (c[m >> 2] | 0) >>> 24;
    a[(d + 13) >> 0] = (c[m >> 2] | 0) >>> 16;
    a[(d + 14) >> 0] = (c[m >> 2] | 0) >>> 8;
    a[(d + 15) >> 0] = c[m >> 2];
    c[m >> 2] = 0;
    m = (b + 16) | 0;
    a[(d + 16) >> 0] = (c[m >> 2] | 0) >>> 24;
    a[(d + 17) >> 0] = (c[m >> 2] | 0) >>> 16;
    a[(d + 18) >> 0] = (c[m >> 2] | 0) >>> 8;
    a[(d + 19) >> 0] = c[m >> 2];
    c[m >> 2] = 0;
    m = (b + 20) | 0;
    a[(d + 20) >> 0] = (c[m >> 2] | 0) >>> 24;
    a[(d + 21) >> 0] = (c[m >> 2] | 0) >>> 16;
    a[(d + 22) >> 0] = (c[m >> 2] | 0) >>> 8;
    a[(d + 23) >> 0] = c[m >> 2];
    c[m >> 2] = 0;
    m = (b + 24) | 0;
    a[(d + 24) >> 0] = (c[m >> 2] | 0) >>> 24;
    a[(d + 25) >> 0] = (c[m >> 2] | 0) >>> 16;
    a[(d + 26) >> 0] = (c[m >> 2] | 0) >>> 8;
    a[(d + 27) >> 0] = c[m >> 2];
    c[m >> 2] = 0;
    m = (b + 28) | 0;
    a[(d + 28) >> 0] = (c[m >> 2] | 0) >>> 24;
    a[(d + 29) >> 0] = (c[m >> 2] | 0) >>> 16;
    a[(d + 30) >> 0] = (c[m >> 2] | 0) >>> 8;
    a[(d + 31) >> 0] = c[m >> 2];
    c[m >> 2] = 0;
    i = l;
    return;
  }
  function ib(a, b) {
    a = a | 0;
    b = b | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      i = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0,
      M = 0,
      N = 0,
      O = 0,
      P = 0,
      Q = 0,
      R = 0,
      S = 0,
      T = 0,
      U = 0,
      V = 0,
      W = 0,
      X = 0,
      Y = 0,
      Z = 0,
      _ = 0,
      $ = 0,
      aa = 0,
      ba = 0,
      ca = 0,
      da = 0,
      ea = 0,
      fa = 0,
      ga = 0,
      ha = 0,
      ia = 0,
      ja = 0,
      ka = 0,
      la = 0,
      ma = 0,
      na = 0;
    s = c[a >> 2] | 0;
    q = (a + 4) | 0;
    r = c[q >> 2] | 0;
    o = (a + 8) | 0;
    p = c[o >> 2] | 0;
    m = (a + 12) | 0;
    j = (a + 16) | 0;
    l = c[j >> 2] | 0;
    h = (a + 20) | 0;
    i = c[h >> 2] | 0;
    f = (a + 24) | 0;
    g = c[f >> 2] | 0;
    e = (a + 28) | 0;
    la =
      ((d[(b + 1) >> 0] | 0) << 16) |
      ((d[b >> 0] | 0) << 24) |
      ((d[(b + 2) >> 0] | 0) << 8) |
      (d[(b + 3) >> 0] | 0);
    ka =
      ((c[e >> 2] | 0) +
        1116352408 +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7))) +
        (((g ^ i) & l) ^ g) +
        la) |
      0;
    n = (ka + (c[m >> 2] | 0)) | 0;
    ka =
      ((((s >>> 2) | (s << 30)) ^
        ((s >>> 13) | (s << 19)) ^
        ((s >>> 22) | (s << 10))) +
        ((p & (r | s)) | (r & s)) +
        ka) |
      0;
    na = ((d[(b + 5) >> 0] | 0) << 16) | ((d[(b + 4) >> 0] | 0) << 24);
    ma = d[(b + 7) >> 0] | 0;
    ha = na | ((d[(b + 6) >> 0] | 0) << 8) | ma;
    g =
      (g +
        1899447441 +
        ((n & (i ^ l)) ^ i) +
        ha +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((ka >>> 2) | (ka << 30)) ^
        ((ka >>> 13) | (ka << 19)) ^
        ((ka >>> 22) | (ka << 10))) +
        (((ka | s) & r) | (ka & s)) +
        g) |
      0;
    ja = ((d[(b + 9) >> 0] | 0) << 16) | ((d[(b + 8) >> 0] | 0) << 24);
    ia = d[(b + 11) >> 0] | 0;
    t = ja | ((d[(b + 10) >> 0] | 0) << 8) | ia;
    i =
      (i +
        -1245643825 +
        t +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | ka) & s) | (g & ka)) +
        i) |
      0;
    ga = ((d[(b + 13) >> 0] | 0) << 16) | ((d[(b + 12) >> 0] | 0) << 24);
    fa = d[(b + 15) >> 0] | 0;
    x = ga | ((d[(b + 14) >> 0] | 0) << 8) | fa;
    l =
      (l +
        -373957723 +
        x +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + s) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & ka) | (i & g)) +
        l) |
      0;
    ea = ((d[(b + 17) >> 0] | 0) << 16) | ((d[(b + 16) >> 0] | 0) << 24);
    da = d[(b + 19) >> 0] | 0;
    E = ea | ((d[(b + 18) >> 0] | 0) << 8) | da;
    n =
      (n +
        961987163 +
        E +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    ka = (n + ka) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    ca = ((d[(b + 21) >> 0] | 0) << 16) | ((d[(b + 20) >> 0] | 0) << 24);
    ba = d[(b + 23) >> 0] | 0;
    C = ca | ((d[(b + 22) >> 0] | 0) << 8) | ba;
    p =
      (p +
        1508970993 +
        C +
        ((ka & (k ^ r)) ^ r) +
        (((ka >>> 6) | (ka << 26)) ^
          ((ka >>> 11) | (ka << 21)) ^
          ((ka >>> 25) | (ka << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    aa = ((d[(b + 25) >> 0] | 0) << 16) | ((d[(b + 24) >> 0] | 0) << 24);
    $ = d[(b + 27) >> 0] | 0;
    A = aa | ((d[(b + 26) >> 0] | 0) << 8) | $;
    r =
      (r +
        -1841331548 +
        A +
        ((g & (ka ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    _ = ((d[(b + 29) >> 0] | 0) << 16) | ((d[(b + 28) >> 0] | 0) << 24);
    Z = d[(b + 31) >> 0] | 0;
    y = _ | ((d[(b + 30) >> 0] | 0) << 8) | Z;
    k =
      (k +
        -1424204075 +
        y +
        ((i & (g ^ ka)) ^ ka) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    l = (k + l) | 0;
    k =
      ((((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
        (((r | p) & n) | (r & p)) +
        k) |
      0;
    Y = ((d[(b + 33) >> 0] | 0) << 16) | ((d[(b + 32) >> 0] | 0) << 24);
    X = d[(b + 35) >> 0] | 0;
    I = Y | ((d[(b + 34) >> 0] | 0) << 8) | X;
    ka =
      (ka +
        -670586216 +
        I +
        ((l & (i ^ g)) ^ g) +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7)))) |
      0;
    n = (ka + n) | 0;
    ka =
      ((((k >>> 2) | (k << 30)) ^
        ((k >>> 13) | (k << 19)) ^
        ((k >>> 22) | (k << 10))) +
        (((k | r) & p) | (k & r)) +
        ka) |
      0;
    W = ((d[(b + 37) >> 0] | 0) << 16) | ((d[(b + 36) >> 0] | 0) << 24);
    V = d[(b + 39) >> 0] | 0;
    H = W | ((d[(b + 38) >> 0] | 0) << 8) | V;
    g =
      (g +
        310598401 +
        H +
        ((n & (l ^ i)) ^ i) +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((ka >>> 2) | (ka << 30)) ^
        ((ka >>> 13) | (ka << 19)) ^
        ((ka >>> 22) | (ka << 10))) +
        (((ka | k) & r) | (ka & k)) +
        g) |
      0;
    U = ((d[(b + 41) >> 0] | 0) << 16) | ((d[(b + 40) >> 0] | 0) << 24);
    T = d[(b + 43) >> 0] | 0;
    G = U | ((d[(b + 42) >> 0] | 0) << 8) | T;
    i =
      (i +
        607225278 +
        G +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | ka) & k) | (g & ka)) +
        i) |
      0;
    S = ((d[(b + 45) >> 0] | 0) << 16) | ((d[(b + 44) >> 0] | 0) << 24);
    R = d[(b + 47) >> 0] | 0;
    F = S | ((d[(b + 46) >> 0] | 0) << 8) | R;
    l =
      (l +
        1426881987 +
        F +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + k) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & ka) | (i & g)) +
        l) |
      0;
    Q = ((d[(b + 49) >> 0] | 0) << 16) | ((d[(b + 48) >> 0] | 0) << 24);
    P = d[(b + 51) >> 0] | 0;
    D = Q | ((d[(b + 50) >> 0] | 0) << 8) | P;
    n =
      (D +
        1925078388 +
        n +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    ka = (n + ka) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    O = ((d[(b + 53) >> 0] | 0) << 16) | ((d[(b + 52) >> 0] | 0) << 24);
    N = d[(b + 55) >> 0] | 0;
    B = O | ((d[(b + 54) >> 0] | 0) << 8) | N;
    p =
      (B +
        -2132889090 +
        p +
        ((ka & (k ^ r)) ^ r) +
        (((ka >>> 6) | (ka << 26)) ^
          ((ka >>> 11) | (ka << 21)) ^
          ((ka >>> 25) | (ka << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    M = ((d[(b + 57) >> 0] | 0) << 16) | ((d[(b + 56) >> 0] | 0) << 24);
    v = M | ((d[(b + 58) >> 0] | 0) << 8);
    L = d[(b + 59) >> 0] | 0;
    z = v | L;
    r =
      (z +
        -1680079193 +
        r +
        ((g & (ka ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    K = ((d[(b + 61) >> 0] | 0) << 16) | ((d[(b + 60) >> 0] | 0) << 24);
    u = K | ((d[(b + 62) >> 0] | 0) << 8);
    J = d[(b + 63) >> 0] | 0;
    w = u | J;
    k =
      (w +
        -1046744716 +
        k +
        ((i & (g ^ ka)) ^ ka) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    l = (k + l) | 0;
    k =
      ((((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
        (((r | p) & n) | (r & p)) +
        k) |
      0;
    v =
      ((((ha << 14) | (na >>> 18)) ^ (ha >>> 3) ^ ((ha >>> 7) | (ma << 25))) +
        la +
        H +
        (((z << 13) | (M >>> 19)) ^ (v >>> 10) ^ ((z << 15) | (M >>> 17)))) |
      0;
    b =
      (v +
        -459576895 +
        ka +
        ((l & (i ^ g)) ^ g) +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7)))) |
      0;
    n = (b + n) | 0;
    b =
      ((((k >>> 2) | (k << 30)) ^
        ((k >>> 13) | (k << 19)) ^
        ((k >>> 22) | (k << 10))) +
        (((k | r) & p) | (k & r)) +
        b) |
      0;
    u =
      ((((t << 14) | (ja >>> 18)) ^ (t >>> 3) ^ ((t >>> 7) | (ia << 25))) +
        ha +
        G +
        (((w << 13) | (K >>> 19)) ^ (u >>> 10) ^ ((w << 15) | (K >>> 17)))) |
      0;
    g =
      (u +
        -272742522 +
        g +
        ((n & (l ^ i)) ^ i) +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((b >>> 2) | (b << 30)) ^
        ((b >>> 13) | (b << 19)) ^
        ((b >>> 22) | (b << 10))) +
        (((b | k) & r) | (b & k)) +
        g) |
      0;
    t =
      ((((x << 14) | (ga >>> 18)) ^ (x >>> 3) ^ ((x >>> 7) | (fa << 25))) +
        t +
        F +
        (((v >>> 19) | (v << 13)) ^ (v >>> 10) ^ ((v >>> 17) | (v << 15)))) |
      0;
    i =
      (t +
        264347078 +
        i +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | b) & k) | (g & b)) +
        i) |
      0;
    x =
      ((((E << 14) | (ea >>> 18)) ^ (E >>> 3) ^ ((E >>> 7) | (da << 25))) +
        x +
        D +
        (((u >>> 19) | (u << 13)) ^ (u >>> 10) ^ ((u >>> 17) | (u << 15)))) |
      0;
    l =
      (x +
        604807628 +
        l +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + k) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & b) | (i & g)) +
        l) |
      0;
    E =
      ((((C << 14) | (ca >>> 18)) ^ (C >>> 3) ^ ((C >>> 7) | (ba << 25))) +
        E +
        B +
        (((t >>> 19) | (t << 13)) ^ (t >>> 10) ^ ((t >>> 17) | (t << 15)))) |
      0;
    n =
      (E +
        770255983 +
        n +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    b = (n + b) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    C =
      ((((A << 14) | (aa >>> 18)) ^ (A >>> 3) ^ ((A >>> 7) | ($ << 25))) +
        C +
        z +
        (((x >>> 19) | (x << 13)) ^ (x >>> 10) ^ ((x >>> 17) | (x << 15)))) |
      0;
    p =
      (C +
        1249150122 +
        p +
        ((b & (k ^ r)) ^ r) +
        (((b >>> 6) | (b << 26)) ^
          ((b >>> 11) | (b << 21)) ^
          ((b >>> 25) | (b << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    A =
      ((((y << 14) | (_ >>> 18)) ^ (y >>> 3) ^ ((y >>> 7) | (Z << 25))) +
        A +
        w +
        (((E >>> 19) | (E << 13)) ^ (E >>> 10) ^ ((E >>> 17) | (E << 15)))) |
      0;
    r =
      (A +
        1555081692 +
        r +
        ((g & (b ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    y =
      ((((I << 14) | (Y >>> 18)) ^ (I >>> 3) ^ ((I >>> 7) | (X << 25))) +
        y +
        v +
        (((C >>> 19) | (C << 13)) ^ (C >>> 10) ^ ((C >>> 17) | (C << 15)))) |
      0;
    k =
      (y +
        1996064986 +
        k +
        ((i & (g ^ b)) ^ b) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    l = (k + l) | 0;
    k =
      ((((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
        (((r | p) & n) | (r & p)) +
        k) |
      0;
    I =
      ((((H << 14) | (W >>> 18)) ^ (H >>> 3) ^ ((H >>> 7) | (V << 25))) +
        I +
        u +
        (((A >>> 19) | (A << 13)) ^ (A >>> 10) ^ ((A >>> 17) | (A << 15)))) |
      0;
    b =
      (I +
        -1740746414 +
        b +
        ((l & (i ^ g)) ^ g) +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7)))) |
      0;
    n = (b + n) | 0;
    b =
      ((((k >>> 2) | (k << 30)) ^
        ((k >>> 13) | (k << 19)) ^
        ((k >>> 22) | (k << 10))) +
        (((k | r) & p) | (k & r)) +
        b) |
      0;
    H =
      ((((G << 14) | (U >>> 18)) ^ (G >>> 3) ^ ((G >>> 7) | (T << 25))) +
        H +
        t +
        (((y >>> 19) | (y << 13)) ^ (y >>> 10) ^ ((y >>> 17) | (y << 15)))) |
      0;
    g =
      (H +
        -1473132947 +
        g +
        ((n & (l ^ i)) ^ i) +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((b >>> 2) | (b << 30)) ^
        ((b >>> 13) | (b << 19)) ^
        ((b >>> 22) | (b << 10))) +
        (((b | k) & r) | (b & k)) +
        g) |
      0;
    G =
      ((((F << 14) | (S >>> 18)) ^ (F >>> 3) ^ ((F >>> 7) | (R << 25))) +
        G +
        x +
        (((I >>> 19) | (I << 13)) ^ (I >>> 10) ^ ((I >>> 17) | (I << 15)))) |
      0;
    i =
      (G +
        -1341970488 +
        i +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | b) & k) | (g & b)) +
        i) |
      0;
    F =
      ((((D << 14) | (Q >>> 18)) ^ (D >>> 3) ^ ((D >>> 7) | (P << 25))) +
        F +
        E +
        (((H >>> 19) | (H << 13)) ^ (H >>> 10) ^ ((H >>> 17) | (H << 15)))) |
      0;
    l =
      (F +
        -1084653625 +
        l +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + k) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & b) | (i & g)) +
        l) |
      0;
    D =
      ((((B << 14) | (O >>> 18)) ^ (B >>> 3) ^ ((B >>> 7) | (N << 25))) +
        D +
        C +
        (((G >>> 19) | (G << 13)) ^ (G >>> 10) ^ ((G >>> 17) | (G << 15)))) |
      0;
    n =
      (D +
        -958395405 +
        n +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    b = (n + b) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    B =
      ((((z << 14) | (M >>> 18)) ^ (z >>> 3) ^ ((z >>> 7) | (L << 25))) +
        B +
        A +
        (((F >>> 19) | (F << 13)) ^ (F >>> 10) ^ ((F >>> 17) | (F << 15)))) |
      0;
    p =
      (B +
        -710438585 +
        p +
        ((b & (k ^ r)) ^ r) +
        (((b >>> 6) | (b << 26)) ^
          ((b >>> 11) | (b << 21)) ^
          ((b >>> 25) | (b << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    z =
      ((((w << 14) | (K >>> 18)) ^ (w >>> 3) ^ ((w >>> 7) | (J << 25))) +
        z +
        y +
        (((D >>> 19) | (D << 13)) ^ (D >>> 10) ^ ((D >>> 17) | (D << 15)))) |
      0;
    r =
      (z +
        113926993 +
        r +
        ((g & (b ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    w =
      ((((v >>> 18) | (v << 14)) ^ (v >>> 3) ^ ((v >>> 7) | (v << 25))) +
        w +
        I +
        (((B >>> 19) | (B << 13)) ^ (B >>> 10) ^ ((B >>> 17) | (B << 15)))) |
      0;
    k =
      (w +
        338241895 +
        k +
        ((i & (g ^ b)) ^ b) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    l = (k + l) | 0;
    k =
      ((((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
        (((r | p) & n) | (r & p)) +
        k) |
      0;
    v =
      ((((u >>> 18) | (u << 14)) ^ (u >>> 3) ^ ((u >>> 7) | (u << 25))) +
        v +
        H +
        (((z >>> 19) | (z << 13)) ^ (z >>> 10) ^ ((z >>> 17) | (z << 15)))) |
      0;
    b =
      (v +
        666307205 +
        b +
        ((l & (i ^ g)) ^ g) +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7)))) |
      0;
    n = (b + n) | 0;
    b =
      ((((k >>> 2) | (k << 30)) ^
        ((k >>> 13) | (k << 19)) ^
        ((k >>> 22) | (k << 10))) +
        (((k | r) & p) | (k & r)) +
        b) |
      0;
    u =
      ((((t >>> 18) | (t << 14)) ^ (t >>> 3) ^ ((t >>> 7) | (t << 25))) +
        u +
        G +
        (((w >>> 19) | (w << 13)) ^ (w >>> 10) ^ ((w >>> 17) | (w << 15)))) |
      0;
    g =
      (u +
        773529912 +
        g +
        ((n & (l ^ i)) ^ i) +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((b >>> 2) | (b << 30)) ^
        ((b >>> 13) | (b << 19)) ^
        ((b >>> 22) | (b << 10))) +
        (((b | k) & r) | (b & k)) +
        g) |
      0;
    t =
      ((((x >>> 18) | (x << 14)) ^ (x >>> 3) ^ ((x >>> 7) | (x << 25))) +
        t +
        F +
        (((v >>> 19) | (v << 13)) ^ (v >>> 10) ^ ((v >>> 17) | (v << 15)))) |
      0;
    i =
      (t +
        1294757372 +
        i +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | b) & k) | (g & b)) +
        i) |
      0;
    x =
      ((((E >>> 18) | (E << 14)) ^ (E >>> 3) ^ ((E >>> 7) | (E << 25))) +
        x +
        D +
        (((u >>> 19) | (u << 13)) ^ (u >>> 10) ^ ((u >>> 17) | (u << 15)))) |
      0;
    l =
      (x +
        1396182291 +
        l +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + k) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & b) | (i & g)) +
        l) |
      0;
    E =
      ((((C >>> 18) | (C << 14)) ^ (C >>> 3) ^ ((C >>> 7) | (C << 25))) +
        E +
        B +
        (((t >>> 19) | (t << 13)) ^ (t >>> 10) ^ ((t >>> 17) | (t << 15)))) |
      0;
    n =
      (E +
        1695183700 +
        n +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    b = (n + b) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    C =
      ((((A >>> 18) | (A << 14)) ^ (A >>> 3) ^ ((A >>> 7) | (A << 25))) +
        C +
        z +
        (((x >>> 19) | (x << 13)) ^ (x >>> 10) ^ ((x >>> 17) | (x << 15)))) |
      0;
    p =
      (C +
        1986661051 +
        p +
        ((b & (k ^ r)) ^ r) +
        (((b >>> 6) | (b << 26)) ^
          ((b >>> 11) | (b << 21)) ^
          ((b >>> 25) | (b << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    A =
      ((((y >>> 18) | (y << 14)) ^ (y >>> 3) ^ ((y >>> 7) | (y << 25))) +
        A +
        w +
        (((E >>> 19) | (E << 13)) ^ (E >>> 10) ^ ((E >>> 17) | (E << 15)))) |
      0;
    r =
      (A +
        -2117940946 +
        r +
        ((g & (b ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    y =
      ((((I >>> 18) | (I << 14)) ^ (I >>> 3) ^ ((I >>> 7) | (I << 25))) +
        y +
        v +
        (((C >>> 19) | (C << 13)) ^ (C >>> 10) ^ ((C >>> 17) | (C << 15)))) |
      0;
    k =
      (y +
        -1838011259 +
        k +
        ((i & (g ^ b)) ^ b) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    l = (k + l) | 0;
    k =
      ((((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
        (((r | p) & n) | (r & p)) +
        k) |
      0;
    I =
      ((((H >>> 18) | (H << 14)) ^ (H >>> 3) ^ ((H >>> 7) | (H << 25))) +
        I +
        u +
        (((A >>> 19) | (A << 13)) ^ (A >>> 10) ^ ((A >>> 17) | (A << 15)))) |
      0;
    b =
      (I +
        -1564481375 +
        b +
        ((l & (i ^ g)) ^ g) +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7)))) |
      0;
    n = (b + n) | 0;
    b =
      ((((k >>> 2) | (k << 30)) ^
        ((k >>> 13) | (k << 19)) ^
        ((k >>> 22) | (k << 10))) +
        (((k | r) & p) | (k & r)) +
        b) |
      0;
    H =
      ((((G >>> 18) | (G << 14)) ^ (G >>> 3) ^ ((G >>> 7) | (G << 25))) +
        H +
        t +
        (((y >>> 19) | (y << 13)) ^ (y >>> 10) ^ ((y >>> 17) | (y << 15)))) |
      0;
    g =
      (H +
        -1474664885 +
        g +
        ((n & (l ^ i)) ^ i) +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((b >>> 2) | (b << 30)) ^
        ((b >>> 13) | (b << 19)) ^
        ((b >>> 22) | (b << 10))) +
        (((b | k) & r) | (b & k)) +
        g) |
      0;
    G =
      ((((F >>> 18) | (F << 14)) ^ (F >>> 3) ^ ((F >>> 7) | (F << 25))) +
        G +
        x +
        (((I >>> 19) | (I << 13)) ^ (I >>> 10) ^ ((I >>> 17) | (I << 15)))) |
      0;
    i =
      (G +
        -1035236496 +
        i +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | b) & k) | (g & b)) +
        i) |
      0;
    F =
      ((((D >>> 18) | (D << 14)) ^ (D >>> 3) ^ ((D >>> 7) | (D << 25))) +
        F +
        E +
        (((H >>> 19) | (H << 13)) ^ (H >>> 10) ^ ((H >>> 17) | (H << 15)))) |
      0;
    l =
      (F +
        -949202525 +
        l +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + k) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & b) | (i & g)) +
        l) |
      0;
    D =
      ((((B >>> 18) | (B << 14)) ^ (B >>> 3) ^ ((B >>> 7) | (B << 25))) +
        D +
        C +
        (((G >>> 19) | (G << 13)) ^ (G >>> 10) ^ ((G >>> 17) | (G << 15)))) |
      0;
    n =
      (D +
        -778901479 +
        n +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    b = (n + b) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    B =
      ((((z >>> 18) | (z << 14)) ^ (z >>> 3) ^ ((z >>> 7) | (z << 25))) +
        B +
        A +
        (((F >>> 19) | (F << 13)) ^ (F >>> 10) ^ ((F >>> 17) | (F << 15)))) |
      0;
    p =
      (B +
        -694614492 +
        p +
        ((b & (k ^ r)) ^ r) +
        (((b >>> 6) | (b << 26)) ^
          ((b >>> 11) | (b << 21)) ^
          ((b >>> 25) | (b << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    z =
      ((((w >>> 18) | (w << 14)) ^ (w >>> 3) ^ ((w >>> 7) | (w << 25))) +
        z +
        y +
        (((D >>> 19) | (D << 13)) ^ (D >>> 10) ^ ((D >>> 17) | (D << 15)))) |
      0;
    r =
      (z +
        -200395387 +
        r +
        ((g & (b ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    w =
      ((((v >>> 18) | (v << 14)) ^ (v >>> 3) ^ ((v >>> 7) | (v << 25))) +
        w +
        I +
        (((B >>> 19) | (B << 13)) ^ (B >>> 10) ^ ((B >>> 17) | (B << 15)))) |
      0;
    k =
      (w +
        275423344 +
        k +
        ((i & (g ^ b)) ^ b) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    l = (k + l) | 0;
    k =
      ((((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
        (((r | p) & n) | (r & p)) +
        k) |
      0;
    v =
      ((((u >>> 18) | (u << 14)) ^ (u >>> 3) ^ ((u >>> 7) | (u << 25))) +
        v +
        H +
        (((z >>> 19) | (z << 13)) ^ (z >>> 10) ^ ((z >>> 17) | (z << 15)))) |
      0;
    b =
      (v +
        430227734 +
        b +
        ((l & (i ^ g)) ^ g) +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7)))) |
      0;
    n = (b + n) | 0;
    b =
      ((((k >>> 2) | (k << 30)) ^
        ((k >>> 13) | (k << 19)) ^
        ((k >>> 22) | (k << 10))) +
        (((k | r) & p) | (k & r)) +
        b) |
      0;
    u =
      ((((t >>> 18) | (t << 14)) ^ (t >>> 3) ^ ((t >>> 7) | (t << 25))) +
        u +
        G +
        (((w >>> 19) | (w << 13)) ^ (w >>> 10) ^ ((w >>> 17) | (w << 15)))) |
      0;
    g =
      (u +
        506948616 +
        g +
        ((n & (l ^ i)) ^ i) +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((b >>> 2) | (b << 30)) ^
        ((b >>> 13) | (b << 19)) ^
        ((b >>> 22) | (b << 10))) +
        (((b | k) & r) | (b & k)) +
        g) |
      0;
    t =
      ((((x >>> 18) | (x << 14)) ^ (x >>> 3) ^ ((x >>> 7) | (x << 25))) +
        t +
        F +
        (((v >>> 19) | (v << 13)) ^ (v >>> 10) ^ ((v >>> 17) | (v << 15)))) |
      0;
    i =
      (t +
        659060556 +
        i +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | b) & k) | (g & b)) +
        i) |
      0;
    x =
      ((((E >>> 18) | (E << 14)) ^ (E >>> 3) ^ ((E >>> 7) | (E << 25))) +
        x +
        D +
        (((u >>> 19) | (u << 13)) ^ (u >>> 10) ^ ((u >>> 17) | (u << 15)))) |
      0;
    l =
      (x +
        883997877 +
        l +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + k) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & b) | (i & g)) +
        l) |
      0;
    E =
      ((((C >>> 18) | (C << 14)) ^ (C >>> 3) ^ ((C >>> 7) | (C << 25))) +
        E +
        B +
        (((t >>> 19) | (t << 13)) ^ (t >>> 10) ^ ((t >>> 17) | (t << 15)))) |
      0;
    n =
      (E +
        958139571 +
        n +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    b = (n + b) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    C =
      ((((A >>> 18) | (A << 14)) ^ (A >>> 3) ^ ((A >>> 7) | (A << 25))) +
        C +
        z +
        (((x >>> 19) | (x << 13)) ^ (x >>> 10) ^ ((x >>> 17) | (x << 15)))) |
      0;
    p =
      (C +
        1322822218 +
        p +
        ((b & (k ^ r)) ^ r) +
        (((b >>> 6) | (b << 26)) ^
          ((b >>> 11) | (b << 21)) ^
          ((b >>> 25) | (b << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    A =
      ((((y >>> 18) | (y << 14)) ^ (y >>> 3) ^ ((y >>> 7) | (y << 25))) +
        A +
        w +
        (((E >>> 19) | (E << 13)) ^ (E >>> 10) ^ ((E >>> 17) | (E << 15)))) |
      0;
    r =
      (A +
        1537002063 +
        r +
        ((g & (b ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    y =
      ((((I >>> 18) | (I << 14)) ^ (I >>> 3) ^ ((I >>> 7) | (I << 25))) +
        y +
        v +
        (((C >>> 19) | (C << 13)) ^ (C >>> 10) ^ ((C >>> 17) | (C << 15)))) |
      0;
    k =
      (y +
        1747873779 +
        k +
        ((i & (g ^ b)) ^ b) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    l = (k + l) | 0;
    k =
      ((((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
        (((r | p) & n) | (r & p)) +
        k) |
      0;
    u =
      ((((H >>> 18) | (H << 14)) ^ (H >>> 3) ^ ((H >>> 7) | (H << 25))) +
        I +
        u +
        (((A >>> 19) | (A << 13)) ^ (A >>> 10) ^ ((A >>> 17) | (A << 15)))) |
      0;
    b =
      (u +
        1955562222 +
        b +
        ((l & (i ^ g)) ^ g) +
        (((l >>> 6) | (l << 26)) ^
          ((l >>> 11) | (l << 21)) ^
          ((l >>> 25) | (l << 7)))) |
      0;
    n = (b + n) | 0;
    b =
      ((((k >>> 2) | (k << 30)) ^
        ((k >>> 13) | (k << 19)) ^
        ((k >>> 22) | (k << 10))) +
        (((k | r) & p) | (k & r)) +
        b) |
      0;
    t =
      ((((G >>> 18) | (G << 14)) ^ (G >>> 3) ^ ((G >>> 7) | (G << 25))) +
        H +
        t +
        (((y >>> 19) | (y << 13)) ^ (y >>> 10) ^ ((y >>> 17) | (y << 15)))) |
      0;
    g =
      (t +
        2024104815 +
        g +
        ((n & (l ^ i)) ^ i) +
        (((n >>> 6) | (n << 26)) ^
          ((n >>> 11) | (n << 21)) ^
          ((n >>> 25) | (n << 7)))) |
      0;
    p = (g + p) | 0;
    g =
      ((((b >>> 2) | (b << 30)) ^
        ((b >>> 13) | (b << 19)) ^
        ((b >>> 22) | (b << 10))) +
        (((b | k) & r) | (b & k)) +
        g) |
      0;
    x =
      ((((F >>> 18) | (F << 14)) ^ (F >>> 3) ^ ((F >>> 7) | (F << 25))) +
        G +
        x +
        (((u >>> 19) | (u << 13)) ^ (u >>> 10) ^ ((u >>> 17) | (u << 15)))) |
      0;
    i =
      (x +
        -2067236844 +
        i +
        ((p & (n ^ l)) ^ l) +
        (((p >>> 6) | (p << 26)) ^
          ((p >>> 11) | (p << 21)) ^
          ((p >>> 25) | (p << 7)))) |
      0;
    r = (i + r) | 0;
    i =
      ((((g >>> 2) | (g << 30)) ^
        ((g >>> 13) | (g << 19)) ^
        ((g >>> 22) | (g << 10))) +
        (((g | b) & k) | (g & b)) +
        i) |
      0;
    t =
      ((((D >>> 18) | (D << 14)) ^ (D >>> 3) ^ ((D >>> 7) | (D << 25))) +
        F +
        E +
        (((t >>> 19) | (t << 13)) ^ (t >>> 10) ^ ((t >>> 17) | (t << 15)))) |
      0;
    l =
      (t +
        -1933114872 +
        l +
        ((r & (p ^ n)) ^ n) +
        (((r >>> 6) | (r << 26)) ^
          ((r >>> 11) | (r << 21)) ^
          ((r >>> 25) | (r << 7)))) |
      0;
    k = (l + k) | 0;
    l =
      ((((i >>> 2) | (i << 30)) ^
        ((i >>> 13) | (i << 19)) ^
        ((i >>> 22) | (i << 10))) +
        (((i | g) & b) | (i & g)) +
        l) |
      0;
    x =
      ((((B >>> 18) | (B << 14)) ^ (B >>> 3) ^ ((B >>> 7) | (B << 25))) +
        D +
        C +
        (((x >>> 19) | (x << 13)) ^ (x >>> 10) ^ ((x >>> 17) | (x << 15)))) |
      0;
    n =
      (x +
        -1866530822 +
        n +
        ((k & (r ^ p)) ^ p) +
        (((k >>> 6) | (k << 26)) ^
          ((k >>> 11) | (k << 21)) ^
          ((k >>> 25) | (k << 7)))) |
      0;
    b = (n + b) | 0;
    n =
      ((((l >>> 2) | (l << 30)) ^
        ((l >>> 13) | (l << 19)) ^
        ((l >>> 22) | (l << 10))) +
        (((l | i) & g) | (l & i)) +
        n) |
      0;
    t =
      ((((z >>> 18) | (z << 14)) ^ (z >>> 3) ^ ((z >>> 7) | (z << 25))) +
        B +
        A +
        (((t >>> 19) | (t << 13)) ^ (t >>> 10) ^ ((t >>> 17) | (t << 15)))) |
      0;
    p =
      (t +
        -1538233109 +
        p +
        ((b & (k ^ r)) ^ r) +
        (((b >>> 6) | (b << 26)) ^
          ((b >>> 11) | (b << 21)) ^
          ((b >>> 25) | (b << 7)))) |
      0;
    g = (p + g) | 0;
    p =
      ((((n >>> 2) | (n << 30)) ^
        ((n >>> 13) | (n << 19)) ^
        ((n >>> 22) | (n << 10))) +
        (((n | l) & i) | (n & l)) +
        p) |
      0;
    r =
      (z +
        -1090935817 +
        (((w >>> 18) | (w << 14)) ^ (w >>> 3) ^ ((w >>> 7) | (w << 25))) +
        y +
        (((x >>> 19) | (x << 13)) ^ (x >>> 10) ^ ((x >>> 17) | (x << 15))) +
        r +
        ((g & (b ^ k)) ^ k) +
        (((g >>> 6) | (g << 26)) ^
          ((g >>> 11) | (g << 21)) ^
          ((g >>> 25) | (g << 7)))) |
      0;
    i = (r + i) | 0;
    r =
      ((((p >>> 2) | (p << 30)) ^
        ((p >>> 13) | (p << 19)) ^
        ((p >>> 22) | (p << 10))) +
        (((p | n) & l) | (p & n)) +
        r) |
      0;
    k =
      (w +
        -965641998 +
        (((v >>> 18) | (v << 14)) ^ (v >>> 3) ^ ((v >>> 7) | (v << 25))) +
        u +
        (((t >>> 19) | (t << 13)) ^ (t >>> 10) ^ ((t >>> 17) | (t << 15))) +
        k +
        ((i & (g ^ b)) ^ b) +
        (((i >>> 6) | (i << 26)) ^
          ((i >>> 11) | (i << 21)) ^
          ((i >>> 25) | (i << 7)))) |
      0;
    c[a >> 2] =
      (((r | p) & n) | (r & p)) +
      s +
      (((r >>> 2) | (r << 30)) ^
        ((r >>> 13) | (r << 19)) ^
        ((r >>> 22) | (r << 10))) +
      k;
    c[q >> 2] = r + (c[q >> 2] | 0);
    c[o >> 2] = p + (c[o >> 2] | 0);
    c[m >> 2] = n + (c[m >> 2] | 0);
    c[j >> 2] = l + (c[j >> 2] | 0) + k;
    c[h >> 2] = i + (c[h >> 2] | 0);
    c[f >> 2] = g + (c[f >> 2] | 0);
    c[e >> 2] = b + (c[e >> 2] | 0);
    return;
  }
  function jb(a, b, d) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      p = 0,
      q = 0;
    q = i;
    i = (i + 80) | 0;
    n = q;
    p = (q + 40) | 0;
    l = lb((a * 40) | 0) | 0;
    if (!l) {
      m = c[o >> 2] | 0;
      c[n >> 2] = 560;
      c[(n + 4) >> 2] = 66;
      c[(n + 8) >> 2] = 576;
      qa(m | 0, 16, n | 0) | 0;
      la();
    }
    m = (a | 0) == 0;
    if (m) e = 0;
    else {
      f = 0;
      g = 0;
      while (1) {
        if (!(c[(d + ((g * 124) | 0) + 120) >> 2] | 0)) {
          e = (f + 1) | 0;
          f = (l + ((f * 40) | 0) + 0) | 0;
          h = (d + ((g * 124) | 0) + 80) | 0;
          j = (f + 40) | 0;
          do {
            c[f >> 2] = c[h >> 2];
            f = (f + 4) | 0;
            h = (h + 4) | 0;
          } while ((f | 0) < (j | 0));
        } else e = f;
        g = (g + 1) | 0;
        if ((g | 0) == (a | 0)) break;
        else f = e;
      }
    }
    k = lb((e * 40) | 0) | 0;
    if (!k) {
      j = c[o >> 2] | 0;
      c[n >> 2] = 560;
      c[(n + 4) >> 2] = 66;
      c[(n + 8) >> 2] = 576;
      qa(j | 0, 16, n | 0) | 0;
      la();
    }
    if (e) {
      f = (k + 0) | 0;
      h = (l + 0) | 0;
      j = (f + 40) | 0;
      do {
        c[f >> 2] = c[h >> 2];
        f = (f + 4) | 0;
        h = (h + 4) | 0;
      } while ((f | 0) < (j | 0));
      if (e >>> 0 > 1) {
        g = 1;
        f = 0;
        while (1) {
          Va(
            (k + ((g * 40) | 0)) | 0,
            (k + ((f * 40) | 0)) | 0,
            (l + ((g * 40) | 0)) | 0
          );
          f = (g + 1) | 0;
          if ((f | 0) == (e | 0)) break;
          else {
            j = g;
            g = f;
            f = j;
          }
        }
        e = (e + -1) | 0;
        _a(n, (k + ((e * 40) | 0)) | 0);
        if (e)
          do {
            j = e;
            e = (e + -1) | 0;
            Va((k + ((j * 40) | 0)) | 0, (k + ((e * 40) | 0)) | 0, n);
            Va(n, n, (l + ((j * 40) | 0)) | 0);
          } while ((e | 0) != 0);
      } else _a(n, k);
      f = (k + 0) | 0;
      h = (n + 0) | 0;
      j = (f + 40) | 0;
      do {
        c[f >> 2] = c[h >> 2];
        f = (f + 4) | 0;
        h = (h + 4) | 0;
      } while ((f | 0) < (j | 0));
    }
    mb(l);
    if (m) {
      mb(k);
      i = q;
      return;
    }
    e = 0;
    f = 0;
    do {
      m = c[(d + ((f * 124) | 0) + 120) >> 2] | 0;
      c[(b + ((f * 84) | 0) + 80) >> 2] = m;
      if (!m) {
        m = (k + ((e * 40) | 0)) | 0;
        Ua(n, m);
        Va(p, n, m);
        Va((b + ((f * 84) | 0)) | 0, (d + ((f * 124) | 0)) | 0, n);
        Va((b + ((f * 84) | 0) + 40) | 0, (d + ((f * 124) | 0) + 40) | 0, p);
        e = (e + 1) | 0;
      }
      f = (f + 1) | 0;
    } while ((f | 0) != (a | 0));
    mb(k);
    i = q;
    return;
  }
  function kb(a, b) {
    a = a | 0;
    b = b | 0;
    var d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0;
    g = i;
    i = (i + 80) | 0;
    d = (g + 40) | 0;
    e = g;
    f = (d + 0) | 0;
    h = (b + 0) | 0;
    j = (f + 40) | 0;
    do {
      c[f >> 2] = c[h >> 2];
      f = (f + 4) | 0;
      h = (h + 4) | 0;
    } while ((f | 0) < (j | 0));
    $a(d);
    f = (e + 0) | 0;
    h = (b + 40) | 0;
    j = (f + 40) | 0;
    do {
      c[f >> 2] = c[h >> 2];
      f = (f + 4) | 0;
      h = (h + 4) | 0;
    } while ((f | 0) < (j | 0));
    $a(e);
    j = c[(d + 4) >> 2] | 0;
    c[a >> 2] = (j << 26) | c[d >> 2];
    h = c[(d + 8) >> 2] | 0;
    c[(a + 4) >> 2] = (h << 20) | (j >>> 6);
    j = c[(d + 12) >> 2] | 0;
    c[(a + 8) >> 2] = (j << 14) | (h >>> 12);
    h = c[(d + 16) >> 2] | 0;
    c[(a + 12) >> 2] = (h << 8) | (j >>> 18);
    j = c[(d + 24) >> 2] | 0;
    c[(a + 16) >> 2] = (c[(d + 20) >> 2] << 2) | (h >>> 24) | (j << 28);
    h = c[(d + 28) >> 2] | 0;
    c[(a + 20) >> 2] = (h << 22) | (j >>> 4);
    j = c[(d + 32) >> 2] | 0;
    c[(a + 24) >> 2] = (j << 16) | (h >>> 10);
    c[(a + 28) >> 2] = (c[(d + 36) >> 2] << 10) | (j >>> 16);
    j = c[(e + 4) >> 2] | 0;
    c[(a + 32) >> 2] = (j << 26) | c[e >> 2];
    h = c[(e + 8) >> 2] | 0;
    c[(a + 36) >> 2] = (h << 20) | (j >>> 6);
    j = c[(e + 12) >> 2] | 0;
    c[(a + 40) >> 2] = (j << 14) | (h >>> 12);
    h = c[(e + 16) >> 2] | 0;
    c[(a + 44) >> 2] = (h << 8) | (j >>> 18);
    j = c[(e + 24) >> 2] | 0;
    c[(a + 48) >> 2] = (c[(e + 20) >> 2] << 2) | (h >>> 24) | (j << 28);
    h = c[(e + 28) >> 2] | 0;
    c[(a + 52) >> 2] = (h << 22) | (j >>> 4);
    j = c[(e + 32) >> 2] | 0;
    c[(a + 56) >> 2] = (j << 16) | (h >>> 10);
    c[(a + 60) >> 2] = (c[(e + 36) >> 2] << 10) | (j >>> 16);
    i = g;
    return;
  }
  function lb(a) {
    a = a | 0;
    var b = 0,
      d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0,
      x = 0,
      y = 0,
      z = 0,
      A = 0,
      B = 0,
      C = 0,
      D = 0,
      E = 0,
      F = 0,
      G = 0,
      H = 0,
      I = 0,
      J = 0,
      K = 0,
      L = 0;
    L = i;
    do
      if (a >>> 0 < 245) {
        if (a >>> 0 < 11) p = 16;
        else p = (a + 11) & -8;
        a = p >>> 3;
        l = c[162] | 0;
        k = l >>> a;
        if (k & 3) {
          e = (((k & 1) ^ 1) + a) | 0;
          f = e << 1;
          b = (688 + (f << 2)) | 0;
          f = (688 + ((f + 2) << 2)) | 0;
          g = c[f >> 2] | 0;
          h = (g + 8) | 0;
          j = c[h >> 2] | 0;
          do
            if ((b | 0) != (j | 0)) {
              if (j >>> 0 < (c[166] | 0) >>> 0) la();
              d = (j + 12) | 0;
              if ((c[d >> 2] | 0) == (g | 0)) {
                c[d >> 2] = b;
                c[f >> 2] = j;
                break;
              } else la();
            } else c[162] = l & ~(1 << e);
          while (0);
          K = e << 3;
          c[(g + 4) >> 2] = K | 3;
          K = (g + (K | 4)) | 0;
          c[K >> 2] = c[K >> 2] | 1;
          K = h;
          i = L;
          return K | 0;
        }
        j = c[164] | 0;
        if (p >>> 0 > j >>> 0) {
          if (k) {
            f = 2 << a;
            f = (k << a) & (f | (0 - f));
            f = ((f & (0 - f)) + -1) | 0;
            a = (f >>> 12) & 16;
            f = f >>> a;
            e = (f >>> 5) & 8;
            f = f >>> e;
            d = (f >>> 2) & 4;
            f = f >>> d;
            g = (f >>> 1) & 2;
            f = f >>> g;
            h = (f >>> 1) & 1;
            h = ((e | a | d | g | h) + (f >>> h)) | 0;
            f = h << 1;
            g = (688 + (f << 2)) | 0;
            f = (688 + ((f + 2) << 2)) | 0;
            d = c[f >> 2] | 0;
            a = (d + 8) | 0;
            e = c[a >> 2] | 0;
            do
              if ((g | 0) != (e | 0)) {
                if (e >>> 0 < (c[166] | 0) >>> 0) la();
                j = (e + 12) | 0;
                if ((c[j >> 2] | 0) == (d | 0)) {
                  c[j >> 2] = g;
                  c[f >> 2] = e;
                  m = c[164] | 0;
                  break;
                } else la();
              } else {
                c[162] = l & ~(1 << h);
                m = j;
              }
            while (0);
            K = h << 3;
            b = (K - p) | 0;
            c[(d + 4) >> 2] = p | 3;
            k = (d + p) | 0;
            c[(d + (p | 4)) >> 2] = b | 1;
            c[(d + K) >> 2] = b;
            if (m) {
              e = c[167] | 0;
              g = m >>> 3;
              j = g << 1;
              f = (688 + (j << 2)) | 0;
              h = c[162] | 0;
              g = 1 << g;
              if (h & g) {
                h = (688 + ((j + 2) << 2)) | 0;
                j = c[h >> 2] | 0;
                if (j >>> 0 < (c[166] | 0) >>> 0) la();
                else {
                  n = h;
                  o = j;
                }
              } else {
                c[162] = h | g;
                n = (688 + ((j + 2) << 2)) | 0;
                o = f;
              }
              c[n >> 2] = e;
              c[(o + 12) >> 2] = e;
              c[(e + 8) >> 2] = o;
              c[(e + 12) >> 2] = f;
            }
            c[164] = b;
            c[167] = k;
            K = a;
            i = L;
            return K | 0;
          }
          k = c[163] | 0;
          if (k) {
            l = ((k & (0 - k)) + -1) | 0;
            J = (l >>> 12) & 16;
            l = l >>> J;
            I = (l >>> 5) & 8;
            l = l >>> I;
            K = (l >>> 2) & 4;
            l = l >>> K;
            j = (l >>> 1) & 2;
            l = l >>> j;
            m = (l >>> 1) & 1;
            m = c[(952 + (((I | J | K | j | m) + (l >>> m)) << 2)) >> 2] | 0;
            l = ((c[(m + 4) >> 2] & -8) - p) | 0;
            j = m;
            while (1) {
              d = c[(j + 16) >> 2] | 0;
              if (!d) {
                d = c[(j + 20) >> 2] | 0;
                if (!d) break;
              }
              j = ((c[(d + 4) >> 2] & -8) - p) | 0;
              K = j >>> 0 < l >>> 0;
              l = K ? j : l;
              j = d;
              m = K ? d : m;
            }
            k = c[166] | 0;
            if (m >>> 0 < k >>> 0) la();
            b = (m + p) | 0;
            if (m >>> 0 >= b >>> 0) la();
            a = c[(m + 24) >> 2] | 0;
            g = c[(m + 12) >> 2] | 0;
            do
              if ((g | 0) == (m | 0)) {
                h = (m + 20) | 0;
                j = c[h >> 2] | 0;
                if (!j) {
                  h = (m + 16) | 0;
                  j = c[h >> 2] | 0;
                  if (!j) {
                    e = 0;
                    break;
                  }
                }
                while (1) {
                  g = (j + 20) | 0;
                  f = c[g >> 2] | 0;
                  if (f) {
                    j = f;
                    h = g;
                    continue;
                  }
                  g = (j + 16) | 0;
                  f = c[g >> 2] | 0;
                  if (!f) break;
                  else {
                    j = f;
                    h = g;
                  }
                }
                if (h >>> 0 < k >>> 0) la();
                else {
                  c[h >> 2] = 0;
                  e = j;
                  break;
                }
              } else {
                f = c[(m + 8) >> 2] | 0;
                if (f >>> 0 < k >>> 0) la();
                j = (f + 12) | 0;
                if ((c[j >> 2] | 0) != (m | 0)) la();
                h = (g + 8) | 0;
                if ((c[h >> 2] | 0) == (m | 0)) {
                  c[j >> 2] = g;
                  c[h >> 2] = f;
                  e = g;
                  break;
                } else la();
              }
            while (0);
            do
              if (a) {
                j = c[(m + 28) >> 2] | 0;
                h = (952 + (j << 2)) | 0;
                if ((m | 0) == (c[h >> 2] | 0)) {
                  c[h >> 2] = e;
                  if (!e) {
                    c[163] = c[163] & ~(1 << j);
                    break;
                  }
                } else {
                  if (a >>> 0 < (c[166] | 0) >>> 0) la();
                  j = (a + 16) | 0;
                  if ((c[j >> 2] | 0) == (m | 0)) c[j >> 2] = e;
                  else c[(a + 20) >> 2] = e;
                  if (!e) break;
                }
                h = c[166] | 0;
                if (e >>> 0 < h >>> 0) la();
                c[(e + 24) >> 2] = a;
                j = c[(m + 16) >> 2] | 0;
                do
                  if (j)
                    if (j >>> 0 < h >>> 0) la();
                    else {
                      c[(e + 16) >> 2] = j;
                      c[(j + 24) >> 2] = e;
                      break;
                    }
                while (0);
                j = c[(m + 20) >> 2] | 0;
                if (j)
                  if (j >>> 0 < (c[166] | 0) >>> 0) la();
                  else {
                    c[(e + 20) >> 2] = j;
                    c[(j + 24) >> 2] = e;
                    break;
                  }
              }
            while (0);
            if (l >>> 0 < 16) {
              K = (l + p) | 0;
              c[(m + 4) >> 2] = K | 3;
              K = (m + (K + 4)) | 0;
              c[K >> 2] = c[K >> 2] | 1;
            } else {
              c[(m + 4) >> 2] = p | 3;
              c[(m + (p | 4)) >> 2] = l | 1;
              c[(m + (l + p)) >> 2] = l;
              d = c[164] | 0;
              if (d) {
                e = c[167] | 0;
                g = d >>> 3;
                j = g << 1;
                f = (688 + (j << 2)) | 0;
                h = c[162] | 0;
                g = 1 << g;
                if (h & g) {
                  j = (688 + ((j + 2) << 2)) | 0;
                  h = c[j >> 2] | 0;
                  if (h >>> 0 < (c[166] | 0) >>> 0) la();
                  else {
                    r = j;
                    q = h;
                  }
                } else {
                  c[162] = h | g;
                  r = (688 + ((j + 2) << 2)) | 0;
                  q = f;
                }
                c[r >> 2] = e;
                c[(q + 12) >> 2] = e;
                c[(e + 8) >> 2] = q;
                c[(e + 12) >> 2] = f;
              }
              c[164] = l;
              c[167] = b;
            }
            K = (m + 8) | 0;
            i = L;
            return K | 0;
          }
        }
      } else if (a >>> 0 <= 4294967231) {
        a = (a + 11) | 0;
        p = a & -8;
        m = c[163] | 0;
        if (m) {
          j = (0 - p) | 0;
          a = a >>> 8;
          if (a)
            if (p >>> 0 > 16777215) l = 31;
            else {
              q = (((a + 1048320) | 0) >>> 16) & 8;
              r = a << q;
              o = (((r + 520192) | 0) >>> 16) & 4;
              r = r << o;
              l = (((r + 245760) | 0) >>> 16) & 2;
              l = (14 - (o | q | l) + ((r << l) >>> 15)) | 0;
              l = ((p >>> ((l + 7) | 0)) & 1) | (l << 1);
            }
          else l = 0;
          h = c[(952 + (l << 2)) >> 2] | 0;
          a: do
            if (!h) {
              a = 0;
              k = 0;
            } else {
              if ((l | 0) == 31) k = 0;
              else k = (25 - (l >>> 1)) | 0;
              f = j;
              a = 0;
              e = p << k;
              k = 0;
              while (1) {
                g = c[(h + 4) >> 2] & -8;
                j = (g - p) | 0;
                if (j >>> 0 < f >>> 0)
                  if ((g | 0) == (p | 0)) {
                    a = h;
                    k = h;
                    break a;
                  } else k = h;
                else j = f;
                r = c[(h + 20) >> 2] | 0;
                h = c[(h + ((e >>> 31) << 2) + 16) >> 2] | 0;
                a = ((r | 0) == 0) | ((r | 0) == (h | 0)) ? a : r;
                if (!h) break;
                else {
                  f = j;
                  e = e << 1;
                }
              }
            }
          while (0);
          if (((a | 0) == 0) & ((k | 0) == 0)) {
            a = 2 << l;
            a = m & (a | (0 - a));
            if (!a) break;
            r = ((a & (0 - a)) + -1) | 0;
            n = (r >>> 12) & 16;
            r = r >>> n;
            m = (r >>> 5) & 8;
            r = r >>> m;
            o = (r >>> 2) & 4;
            r = r >>> o;
            q = (r >>> 1) & 2;
            r = r >>> q;
            a = (r >>> 1) & 1;
            a = c[(952 + (((m | n | o | q | a) + (r >>> a)) << 2)) >> 2] | 0;
          }
          if (!a) {
            n = j;
            m = k;
          } else
            while (1) {
              r = ((c[(a + 4) >> 2] & -8) - p) | 0;
              h = r >>> 0 < j >>> 0;
              j = h ? r : j;
              k = h ? a : k;
              h = c[(a + 16) >> 2] | 0;
              if (h) {
                a = h;
                continue;
              }
              a = c[(a + 20) >> 2] | 0;
              if (!a) {
                n = j;
                m = k;
                break;
              }
            }
          if ((m | 0) != 0 ? n >>> 0 < (((c[164] | 0) - p) | 0) >>> 0 : 0) {
            k = c[166] | 0;
            if (m >>> 0 < k >>> 0) la();
            o = (m + p) | 0;
            if (m >>> 0 >= o >>> 0) la();
            a = c[(m + 24) >> 2] | 0;
            g = c[(m + 12) >> 2] | 0;
            do
              if ((g | 0) == (m | 0)) {
                h = (m + 20) | 0;
                j = c[h >> 2] | 0;
                if (!j) {
                  h = (m + 16) | 0;
                  j = c[h >> 2] | 0;
                  if (!j) {
                    d = 0;
                    break;
                  }
                }
                while (1) {
                  g = (j + 20) | 0;
                  f = c[g >> 2] | 0;
                  if (f) {
                    j = f;
                    h = g;
                    continue;
                  }
                  g = (j + 16) | 0;
                  f = c[g >> 2] | 0;
                  if (!f) break;
                  else {
                    j = f;
                    h = g;
                  }
                }
                if (h >>> 0 < k >>> 0) la();
                else {
                  c[h >> 2] = 0;
                  d = j;
                  break;
                }
              } else {
                f = c[(m + 8) >> 2] | 0;
                if (f >>> 0 < k >>> 0) la();
                j = (f + 12) | 0;
                if ((c[j >> 2] | 0) != (m | 0)) la();
                h = (g + 8) | 0;
                if ((c[h >> 2] | 0) == (m | 0)) {
                  c[j >> 2] = g;
                  c[h >> 2] = f;
                  d = g;
                  break;
                } else la();
              }
            while (0);
            do
              if (a) {
                j = c[(m + 28) >> 2] | 0;
                h = (952 + (j << 2)) | 0;
                if ((m | 0) == (c[h >> 2] | 0)) {
                  c[h >> 2] = d;
                  if (!d) {
                    c[163] = c[163] & ~(1 << j);
                    break;
                  }
                } else {
                  if (a >>> 0 < (c[166] | 0) >>> 0) la();
                  j = (a + 16) | 0;
                  if ((c[j >> 2] | 0) == (m | 0)) c[j >> 2] = d;
                  else c[(a + 20) >> 2] = d;
                  if (!d) break;
                }
                h = c[166] | 0;
                if (d >>> 0 < h >>> 0) la();
                c[(d + 24) >> 2] = a;
                j = c[(m + 16) >> 2] | 0;
                do
                  if (j)
                    if (j >>> 0 < h >>> 0) la();
                    else {
                      c[(d + 16) >> 2] = j;
                      c[(j + 24) >> 2] = d;
                      break;
                    }
                while (0);
                j = c[(m + 20) >> 2] | 0;
                if (j)
                  if (j >>> 0 < (c[166] | 0) >>> 0) la();
                  else {
                    c[(d + 20) >> 2] = j;
                    c[(j + 24) >> 2] = d;
                    break;
                  }
              }
            while (0);
            b: do
              if (n >>> 0 >= 16) {
                c[(m + 4) >> 2] = p | 3;
                c[(m + (p | 4)) >> 2] = n | 1;
                c[(m + (n + p)) >> 2] = n;
                j = n >>> 3;
                if (n >>> 0 < 256) {
                  h = j << 1;
                  f = (688 + (h << 2)) | 0;
                  g = c[162] | 0;
                  j = 1 << j;
                  do
                    if (!(g & j)) {
                      c[162] = g | j;
                      b = (688 + ((h + 2) << 2)) | 0;
                      t = f;
                    } else {
                      j = (688 + ((h + 2) << 2)) | 0;
                      h = c[j >> 2] | 0;
                      if (h >>> 0 >= (c[166] | 0) >>> 0) {
                        b = j;
                        t = h;
                        break;
                      }
                      la();
                    }
                  while (0);
                  c[b >> 2] = o;
                  c[(t + 12) >> 2] = o;
                  c[(m + (p + 8)) >> 2] = t;
                  c[(m + (p + 12)) >> 2] = f;
                  break;
                }
                d = n >>> 8;
                if (d)
                  if (n >>> 0 > 16777215) f = 31;
                  else {
                    J = (((d + 1048320) | 0) >>> 16) & 8;
                    K = d << J;
                    I = (((K + 520192) | 0) >>> 16) & 4;
                    K = K << I;
                    f = (((K + 245760) | 0) >>> 16) & 2;
                    f = (14 - (I | J | f) + ((K << f) >>> 15)) | 0;
                    f = ((n >>> ((f + 7) | 0)) & 1) | (f << 1);
                  }
                else f = 0;
                j = (952 + (f << 2)) | 0;
                c[(m + (p + 28)) >> 2] = f;
                c[(m + (p + 20)) >> 2] = 0;
                c[(m + (p + 16)) >> 2] = 0;
                h = c[163] | 0;
                g = 1 << f;
                if (!(h & g)) {
                  c[163] = h | g;
                  c[j >> 2] = o;
                  c[(m + (p + 24)) >> 2] = j;
                  c[(m + (p + 12)) >> 2] = o;
                  c[(m + (p + 8)) >> 2] = o;
                  break;
                }
                j = c[j >> 2] | 0;
                if ((f | 0) == 31) d = 0;
                else d = (25 - (f >>> 1)) | 0;
                c: do
                  if (((c[(j + 4) >> 2] & -8) | 0) != (n | 0)) {
                    f = n << d;
                    while (1) {
                      g = (j + ((f >>> 31) << 2) + 16) | 0;
                      h = c[g >> 2] | 0;
                      if (!h) break;
                      if (((c[(h + 4) >> 2] & -8) | 0) == (n | 0)) {
                        v = h;
                        break c;
                      } else {
                        f = f << 1;
                        j = h;
                      }
                    }
                    if (g >>> 0 < (c[166] | 0) >>> 0) la();
                    else {
                      c[g >> 2] = o;
                      c[(m + (p + 24)) >> 2] = j;
                      c[(m + (p + 12)) >> 2] = o;
                      c[(m + (p + 8)) >> 2] = o;
                      break b;
                    }
                  } else v = j;
                while (0);
                d = (v + 8) | 0;
                b = c[d >> 2] | 0;
                K = c[166] | 0;
                if ((v >>> 0 >= K >>> 0) & (b >>> 0 >= K >>> 0)) {
                  c[(b + 12) >> 2] = o;
                  c[d >> 2] = o;
                  c[(m + (p + 8)) >> 2] = b;
                  c[(m + (p + 12)) >> 2] = v;
                  c[(m + (p + 24)) >> 2] = 0;
                  break;
                } else la();
              } else {
                K = (n + p) | 0;
                c[(m + 4) >> 2] = K | 3;
                K = (m + (K + 4)) | 0;
                c[K >> 2] = c[K >> 2] | 1;
              }
            while (0);
            K = (m + 8) | 0;
            i = L;
            return K | 0;
          }
        }
      } else p = -1;
    while (0);
    k = c[164] | 0;
    if (k >>> 0 >= p >>> 0) {
      b = (k - p) | 0;
      d = c[167] | 0;
      if (b >>> 0 > 15) {
        c[167] = d + p;
        c[164] = b;
        c[(d + (p + 4)) >> 2] = b | 1;
        c[(d + k) >> 2] = b;
        c[(d + 4) >> 2] = p | 3;
      } else {
        c[164] = 0;
        c[167] = 0;
        c[(d + 4) >> 2] = k | 3;
        K = (d + (k + 4)) | 0;
        c[K >> 2] = c[K >> 2] | 1;
      }
      K = (d + 8) | 0;
      i = L;
      return K | 0;
    }
    k = c[165] | 0;
    if (k >>> 0 > p >>> 0) {
      J = (k - p) | 0;
      c[165] = J;
      K = c[168] | 0;
      c[168] = K + p;
      c[(K + (p + 4)) >> 2] = J | 1;
      c[(K + 4) >> 2] = p | 3;
      K = (K + 8) | 0;
      i = L;
      return K | 0;
    }
    do
      if (!(c[280] | 0)) {
        k = wa(30) | 0;
        if (!((k + -1) & k)) {
          c[282] = k;
          c[281] = k;
          c[283] = -1;
          c[284] = -1;
          c[285] = 0;
          c[273] = 0;
          c[280] = ((ha(0) | 0) & -16) ^ 1431655768;
          break;
        } else la();
      }
    while (0);
    l = (p + 48) | 0;
    g = c[282] | 0;
    f = (p + 47) | 0;
    h = (g + f) | 0;
    g = (0 - g) | 0;
    m = h & g;
    if (m >>> 0 <= p >>> 0) {
      K = 0;
      i = L;
      return K | 0;
    }
    a = c[272] | 0;
    if (
      (a | 0) != 0
        ? ((t = c[270] | 0),
          (v = (t + m) | 0),
          (v >>> 0 <= t >>> 0) | (v >>> 0 > a >>> 0))
        : 0
    ) {
      K = 0;
      i = L;
      return K | 0;
    }
    d: do
      if (!(c[273] & 4)) {
        j = c[168] | 0;
        e: do
          if (j) {
            a = 1096 | 0;
            while (1) {
              k = c[a >> 2] | 0;
              if (
                k >>> 0 <= j >>> 0
                  ? ((s = (a + 4) | 0),
                    ((k + (c[s >> 2] | 0)) | 0) >>> 0 > j >>> 0)
                  : 0
              )
                break;
              a = c[(a + 8) >> 2] | 0;
              if (!a) {
                A = 181;
                break e;
              }
            }
            if (a) {
              k = (h - (c[165] | 0)) & g;
              if (k >>> 0 < 2147483647) {
                j = oa(k | 0) | 0;
                if ((j | 0) == (((c[a >> 2] | 0) + (c[s >> 2] | 0)) | 0))
                  A = 190;
                else A = 191;
              } else k = 0;
            } else A = 181;
          } else A = 181;
        while (0);
        do
          if ((A | 0) == 181) {
            j = oa(0) | 0;
            if ((j | 0) != (-1 | 0)) {
              a = j;
              k = c[281] | 0;
              h = (k + -1) | 0;
              if (!(h & a)) k = m;
              else k = (m - a + ((h + a) & (0 - k))) | 0;
              a = c[270] | 0;
              h = (a + k) | 0;
              if ((k >>> 0 > p >>> 0) & (k >>> 0 < 2147483647)) {
                v = c[272] | 0;
                if (
                  (v | 0) != 0 ? (h >>> 0 <= a >>> 0) | (h >>> 0 > v >>> 0) : 0
                ) {
                  k = 0;
                  break;
                }
                h = oa(k | 0) | 0;
                if ((h | 0) == (j | 0)) A = 190;
                else {
                  j = h;
                  A = 191;
                }
              } else k = 0;
            } else k = 0;
          }
        while (0);
        f: do
          if ((A | 0) == 190) {
            if ((j | 0) != (-1 | 0)) {
              w = j;
              s = k;
              A = 201;
              break d;
            }
          } else if ((A | 0) == 191) {
            h = (0 - k) | 0;
            do
              if (
                ((j | 0) != (-1 | 0)) &
                (k >>> 0 < 2147483647) &
                (l >>> 0 > k >>> 0)
                  ? ((u = c[282] | 0),
                    (u = (f - k + u) & (0 - u)),
                    u >>> 0 < 2147483647)
                  : 0
              )
                if ((oa(u | 0) | 0) == (-1 | 0)) {
                  oa(h | 0) | 0;
                  k = 0;
                  break f;
                } else {
                  k = (u + k) | 0;
                  break;
                }
            while (0);
            if ((j | 0) == (-1 | 0)) k = 0;
            else {
              w = j;
              s = k;
              A = 201;
              break d;
            }
          }
        while (0);
        c[273] = c[273] | 4;
        A = 198;
      } else {
        k = 0;
        A = 198;
      }
    while (0);
    if (
      (
        ((A | 0) == 198 ? m >>> 0 < 2147483647 : 0)
          ? ((w = oa(m | 0) | 0),
            (x = oa(0) | 0),
            ((w | 0) != (-1 | 0)) & ((x | 0) != (-1 | 0)) & (w >>> 0 < x >>> 0))
          : 0
      )
        ? ((y = (x - w) | 0), (z = y >>> 0 > ((p + 40) | 0) >>> 0), z)
        : 0
    ) {
      s = z ? y : k;
      A = 201;
    }
    if ((A | 0) == 201) {
      j = ((c[270] | 0) + s) | 0;
      c[270] = j;
      if (j >>> 0 > (c[271] | 0) >>> 0) c[271] = j;
      o = c[168] | 0;
      g: do
        if (o) {
          f = 1096 | 0;
          while (1) {
            k = c[f >> 2] | 0;
            j = (f + 4) | 0;
            h = c[j >> 2] | 0;
            if ((w | 0) == ((k + h) | 0)) {
              A = 213;
              break;
            }
            g = c[(f + 8) >> 2] | 0;
            if (!g) break;
            else f = g;
          }
          if (
            ((A | 0) == 213 ? ((c[(f + 12) >> 2] & 8) | 0) == 0 : 0)
              ? (o >>> 0 >= k >>> 0) & (o >>> 0 < w >>> 0)
              : 0
          ) {
            c[j >> 2] = h + s;
            b = ((c[165] | 0) + s) | 0;
            d = (o + 8) | 0;
            if (!(d & 7)) d = 0;
            else d = (0 - d) & 7;
            K = (b - d) | 0;
            c[168] = o + d;
            c[165] = K;
            c[(o + (d + 4)) >> 2] = K | 1;
            c[(o + (b + 4)) >> 2] = 40;
            c[169] = c[284];
            break;
          }
          k = c[166] | 0;
          if (w >>> 0 < k >>> 0) {
            c[166] = w;
            k = w;
          }
          j = (w + s) | 0;
          g = 1096 | 0;
          while (1) {
            if ((c[g >> 2] | 0) == (j | 0)) {
              A = 223;
              break;
            }
            h = c[(g + 8) >> 2] | 0;
            if (!h) break;
            else g = h;
          }
          if ((A | 0) == 223 ? ((c[(g + 12) >> 2] & 8) | 0) == 0 : 0) {
            c[g >> 2] = w;
            j = (g + 4) | 0;
            c[j >> 2] = (c[j >> 2] | 0) + s;
            j = (w + 8) | 0;
            if (!(j & 7)) r = 0;
            else r = (0 - j) & 7;
            j = (w + (s + 8)) | 0;
            if (!(j & 7)) l = 0;
            else l = (0 - j) & 7;
            j = (w + (l + s)) | 0;
            n = (r + p) | 0;
            q = (w + n) | 0;
            b = (j - (w + r) - p) | 0;
            c[(w + (r + 4)) >> 2] = p | 3;
            h: do
              if ((j | 0) != (o | 0)) {
                if ((j | 0) == (c[167] | 0)) {
                  K = ((c[164] | 0) + b) | 0;
                  c[164] = K;
                  c[167] = q;
                  c[(w + (n + 4)) >> 2] = K | 1;
                  c[(w + (K + n)) >> 2] = K;
                  break;
                }
                d = (s + 4) | 0;
                h = c[(w + (d + l)) >> 2] | 0;
                if (((h & 3) | 0) == 1) {
                  m = h & -8;
                  e = h >>> 3;
                  i: do
                    if (h >>> 0 >= 256) {
                      a = c[(w + ((l | 24) + s)) >> 2] | 0;
                      g = c[(w + (s + 12 + l)) >> 2] | 0;
                      do
                        if ((g | 0) == (j | 0)) {
                          g = l | 16;
                          f = (w + (d + g)) | 0;
                          h = c[f >> 2] | 0;
                          if (!h) {
                            g = (w + (g + s)) | 0;
                            h = c[g >> 2] | 0;
                            if (!h) {
                              H = 0;
                              break;
                            }
                          } else g = f;
                          while (1) {
                            f = (h + 20) | 0;
                            e = c[f >> 2] | 0;
                            if (e) {
                              h = e;
                              g = f;
                              continue;
                            }
                            f = (h + 16) | 0;
                            e = c[f >> 2] | 0;
                            if (!e) break;
                            else {
                              h = e;
                              g = f;
                            }
                          }
                          if (g >>> 0 < k >>> 0) la();
                          else {
                            c[g >> 2] = 0;
                            H = h;
                            break;
                          }
                        } else {
                          f = c[(w + ((l | 8) + s)) >> 2] | 0;
                          if (f >>> 0 < k >>> 0) la();
                          k = (f + 12) | 0;
                          if ((c[k >> 2] | 0) != (j | 0)) la();
                          h = (g + 8) | 0;
                          if ((c[h >> 2] | 0) == (j | 0)) {
                            c[k >> 2] = g;
                            c[h >> 2] = f;
                            H = g;
                            break;
                          } else la();
                        }
                      while (0);
                      if (!a) break;
                      k = c[(w + (s + 28 + l)) >> 2] | 0;
                      h = (952 + (k << 2)) | 0;
                      do
                        if ((j | 0) != (c[h >> 2] | 0)) {
                          if (a >>> 0 < (c[166] | 0) >>> 0) la();
                          k = (a + 16) | 0;
                          if ((c[k >> 2] | 0) == (j | 0)) c[k >> 2] = H;
                          else c[(a + 20) >> 2] = H;
                          if (!H) break i;
                        } else {
                          c[h >> 2] = H;
                          if (H) break;
                          c[163] = c[163] & ~(1 << k);
                          break i;
                        }
                      while (0);
                      h = c[166] | 0;
                      if (H >>> 0 < h >>> 0) la();
                      c[(H + 24) >> 2] = a;
                      k = l | 16;
                      j = c[(w + (k + s)) >> 2] | 0;
                      do
                        if (j)
                          if (j >>> 0 < h >>> 0) la();
                          else {
                            c[(H + 16) >> 2] = j;
                            c[(j + 24) >> 2] = H;
                            break;
                          }
                      while (0);
                      j = c[(w + (d + k)) >> 2] | 0;
                      if (!j) break;
                      if (j >>> 0 < (c[166] | 0) >>> 0) la();
                      else {
                        c[(H + 20) >> 2] = j;
                        c[(j + 24) >> 2] = H;
                        break;
                      }
                    } else {
                      g = c[(w + ((l | 8) + s)) >> 2] | 0;
                      f = c[(w + (s + 12 + l)) >> 2] | 0;
                      h = (688 + ((e << 1) << 2)) | 0;
                      do
                        if ((g | 0) != (h | 0)) {
                          if (g >>> 0 < k >>> 0) la();
                          if ((c[(g + 12) >> 2] | 0) == (j | 0)) break;
                          la();
                        }
                      while (0);
                      if ((f | 0) == (g | 0)) {
                        c[162] = c[162] & ~(1 << e);
                        break;
                      }
                      do
                        if ((f | 0) == (h | 0)) D = (f + 8) | 0;
                        else {
                          if (f >>> 0 < k >>> 0) la();
                          k = (f + 8) | 0;
                          if ((c[k >> 2] | 0) == (j | 0)) {
                            D = k;
                            break;
                          }
                          la();
                        }
                      while (0);
                      c[(g + 12) >> 2] = f;
                      c[D >> 2] = g;
                    }
                  while (0);
                  j = (w + ((m | l) + s)) | 0;
                  k = (m + b) | 0;
                } else k = b;
                j = (j + 4) | 0;
                c[j >> 2] = c[j >> 2] & -2;
                c[(w + (n + 4)) >> 2] = k | 1;
                c[(w + (k + n)) >> 2] = k;
                j = k >>> 3;
                if (k >>> 0 < 256) {
                  h = j << 1;
                  f = (688 + (h << 2)) | 0;
                  g = c[162] | 0;
                  j = 1 << j;
                  do
                    if (!(g & j)) {
                      c[162] = g | j;
                      I = (688 + ((h + 2) << 2)) | 0;
                      J = f;
                    } else {
                      j = (688 + ((h + 2) << 2)) | 0;
                      h = c[j >> 2] | 0;
                      if (h >>> 0 >= (c[166] | 0) >>> 0) {
                        I = j;
                        J = h;
                        break;
                      }
                      la();
                    }
                  while (0);
                  c[I >> 2] = q;
                  c[(J + 12) >> 2] = q;
                  c[(w + (n + 8)) >> 2] = J;
                  c[(w + (n + 12)) >> 2] = f;
                  break;
                }
                d = k >>> 8;
                do
                  if (!d) f = 0;
                  else {
                    if (k >>> 0 > 16777215) {
                      f = 31;
                      break;
                    }
                    I = (((d + 1048320) | 0) >>> 16) & 8;
                    J = d << I;
                    H = (((J + 520192) | 0) >>> 16) & 4;
                    J = J << H;
                    f = (((J + 245760) | 0) >>> 16) & 2;
                    f = (14 - (H | I | f) + ((J << f) >>> 15)) | 0;
                    f = ((k >>> ((f + 7) | 0)) & 1) | (f << 1);
                  }
                while (0);
                j = (952 + (f << 2)) | 0;
                c[(w + (n + 28)) >> 2] = f;
                c[(w + (n + 20)) >> 2] = 0;
                c[(w + (n + 16)) >> 2] = 0;
                h = c[163] | 0;
                g = 1 << f;
                if (!(h & g)) {
                  c[163] = h | g;
                  c[j >> 2] = q;
                  c[(w + (n + 24)) >> 2] = j;
                  c[(w + (n + 12)) >> 2] = q;
                  c[(w + (n + 8)) >> 2] = q;
                  break;
                }
                h = c[j >> 2] | 0;
                if ((f | 0) == 31) j = 0;
                else j = (25 - (f >>> 1)) | 0;
                j: do
                  if (((c[(h + 4) >> 2] & -8) | 0) != (k | 0)) {
                    f = k << j;
                    while (1) {
                      g = (h + ((f >>> 31) << 2) + 16) | 0;
                      j = c[g >> 2] | 0;
                      if (!j) break;
                      if (((c[(j + 4) >> 2] & -8) | 0) == (k | 0)) {
                        K = j;
                        break j;
                      } else {
                        f = f << 1;
                        h = j;
                      }
                    }
                    if (g >>> 0 < (c[166] | 0) >>> 0) la();
                    else {
                      c[g >> 2] = q;
                      c[(w + (n + 24)) >> 2] = h;
                      c[(w + (n + 12)) >> 2] = q;
                      c[(w + (n + 8)) >> 2] = q;
                      break h;
                    }
                  } else K = h;
                while (0);
                d = (K + 8) | 0;
                b = c[d >> 2] | 0;
                J = c[166] | 0;
                if ((K >>> 0 >= J >>> 0) & (b >>> 0 >= J >>> 0)) {
                  c[(b + 12) >> 2] = q;
                  c[d >> 2] = q;
                  c[(w + (n + 8)) >> 2] = b;
                  c[(w + (n + 12)) >> 2] = K;
                  c[(w + (n + 24)) >> 2] = 0;
                  break;
                } else la();
              } else {
                K = ((c[165] | 0) + b) | 0;
                c[165] = K;
                c[168] = q;
                c[(w + (n + 4)) >> 2] = K | 1;
              }
            while (0);
            K = (w + (r | 8)) | 0;
            i = L;
            return K | 0;
          }
          j = 1096 | 0;
          while (1) {
            h = c[j >> 2] | 0;
            if (
              h >>> 0 <= o >>> 0
                ? ((B = c[(j + 4) >> 2] | 0),
                  (C = (h + B) | 0),
                  C >>> 0 > o >>> 0)
                : 0
            )
              break;
            j = c[(j + 8) >> 2] | 0;
          }
          j = (h + (B + -39)) | 0;
          if (!(j & 7)) j = 0;
          else j = (0 - j) & 7;
          g = (h + (B + -47 + j)) | 0;
          g = g >>> 0 < ((o + 16) | 0) >>> 0 ? o : g;
          h = (g + 8) | 0;
          j = (w + 8) | 0;
          if (!(j & 7)) j = 0;
          else j = (0 - j) & 7;
          K = (s + -40 - j) | 0;
          c[168] = w + j;
          c[165] = K;
          c[(w + (j + 4)) >> 2] = K | 1;
          c[(w + (s + -36)) >> 2] = 40;
          c[169] = c[284];
          c[(g + 4) >> 2] = 27;
          c[(h + 0) >> 2] = c[274];
          c[(h + 4) >> 2] = c[275];
          c[(h + 8) >> 2] = c[276];
          c[(h + 12) >> 2] = c[277];
          c[274] = w;
          c[275] = s;
          c[277] = 0;
          c[276] = h;
          j = (g + 28) | 0;
          c[j >> 2] = 7;
          if (((g + 32) | 0) >>> 0 < C >>> 0)
            do {
              K = j;
              j = (j + 4) | 0;
              c[j >> 2] = 7;
            } while (((K + 8) | 0) >>> 0 < C >>> 0);
          if ((g | 0) != (o | 0)) {
            k = (g - o) | 0;
            j = (o + (k + 4)) | 0;
            c[j >> 2] = c[j >> 2] & -2;
            c[(o + 4) >> 2] = k | 1;
            c[(o + k) >> 2] = k;
            j = k >>> 3;
            if (k >>> 0 < 256) {
              h = j << 1;
              f = (688 + (h << 2)) | 0;
              g = c[162] | 0;
              j = 1 << j;
              do
                if (!(g & j)) {
                  c[162] = g | j;
                  E = (688 + ((h + 2) << 2)) | 0;
                  F = f;
                } else {
                  d = (688 + ((h + 2) << 2)) | 0;
                  b = c[d >> 2] | 0;
                  if (b >>> 0 >= (c[166] | 0) >>> 0) {
                    E = d;
                    F = b;
                    break;
                  }
                  la();
                }
              while (0);
              c[E >> 2] = o;
              c[(F + 12) >> 2] = o;
              c[(o + 8) >> 2] = F;
              c[(o + 12) >> 2] = f;
              break;
            }
            d = k >>> 8;
            if (d)
              if (k >>> 0 > 16777215) j = 31;
              else {
                J = (((d + 1048320) | 0) >>> 16) & 8;
                K = d << J;
                I = (((K + 520192) | 0) >>> 16) & 4;
                K = K << I;
                j = (((K + 245760) | 0) >>> 16) & 2;
                j = (14 - (I | J | j) + ((K << j) >>> 15)) | 0;
                j = ((k >>> ((j + 7) | 0)) & 1) | (j << 1);
              }
            else j = 0;
            d = (952 + (j << 2)) | 0;
            c[(o + 28) >> 2] = j;
            c[(o + 20) >> 2] = 0;
            c[(o + 16) >> 2] = 0;
            b = c[163] | 0;
            e = 1 << j;
            if (!(b & e)) {
              c[163] = b | e;
              c[d >> 2] = o;
              c[(o + 24) >> 2] = d;
              c[(o + 12) >> 2] = o;
              c[(o + 8) >> 2] = o;
              break;
            }
            e = c[d >> 2] | 0;
            if ((j | 0) == 31) d = 0;
            else d = (25 - (j >>> 1)) | 0;
            k: do
              if (((c[(e + 4) >> 2] & -8) | 0) != (k | 0)) {
                j = k << d;
                while (1) {
                  b = (e + ((j >>> 31) << 2) + 16) | 0;
                  d = c[b >> 2] | 0;
                  if (!d) break;
                  if (((c[(d + 4) >> 2] & -8) | 0) == (k | 0)) {
                    G = d;
                    break k;
                  } else {
                    j = j << 1;
                    e = d;
                  }
                }
                if (b >>> 0 < (c[166] | 0) >>> 0) la();
                else {
                  c[b >> 2] = o;
                  c[(o + 24) >> 2] = e;
                  c[(o + 12) >> 2] = o;
                  c[(o + 8) >> 2] = o;
                  break g;
                }
              } else G = e;
            while (0);
            d = (G + 8) | 0;
            b = c[d >> 2] | 0;
            K = c[166] | 0;
            if ((G >>> 0 >= K >>> 0) & (b >>> 0 >= K >>> 0)) {
              c[(b + 12) >> 2] = o;
              c[d >> 2] = o;
              c[(o + 8) >> 2] = b;
              c[(o + 12) >> 2] = G;
              c[(o + 24) >> 2] = 0;
              break;
            } else la();
          }
        } else {
          K = c[166] | 0;
          if (((K | 0) == 0) | (w >>> 0 < K >>> 0)) c[166] = w;
          c[274] = w;
          c[275] = s;
          c[277] = 0;
          c[171] = c[280];
          c[170] = -1;
          d = 0;
          do {
            K = d << 1;
            J = (688 + (K << 2)) | 0;
            c[(688 + ((K + 3) << 2)) >> 2] = J;
            c[(688 + ((K + 2) << 2)) >> 2] = J;
            d = (d + 1) | 0;
          } while ((d | 0) != 32);
          d = (w + 8) | 0;
          if (!(d & 7)) d = 0;
          else d = (0 - d) & 7;
          K = (s + -40 - d) | 0;
          c[168] = w + d;
          c[165] = K;
          c[(w + (d + 4)) >> 2] = K | 1;
          c[(w + (s + -36)) >> 2] = 40;
          c[169] = c[284];
        }
      while (0);
      b = c[165] | 0;
      if (b >>> 0 > p >>> 0) {
        J = (b - p) | 0;
        c[165] = J;
        K = c[168] | 0;
        c[168] = K + p;
        c[(K + (p + 4)) >> 2] = J | 1;
        c[(K + 4) >> 2] = p | 3;
        K = (K + 8) | 0;
        i = L;
        return K | 0;
      }
    }
    c[(xa() | 0) >> 2] = 12;
    K = 0;
    i = L;
    return K | 0;
  }
  function mb(a) {
    a = a | 0;
    var b = 0,
      d = 0,
      e = 0,
      f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0,
      q = 0,
      r = 0,
      s = 0,
      t = 0,
      u = 0,
      v = 0,
      w = 0;
    w = i;
    if (!a) {
      i = w;
      return;
    }
    g = (a + -8) | 0;
    h = c[166] | 0;
    if (g >>> 0 < h >>> 0) la();
    f = c[(a + -4) >> 2] | 0;
    e = f & 3;
    if ((e | 0) == 1) la();
    p = f & -8;
    r = (a + (p + -8)) | 0;
    do
      if (!(f & 1)) {
        g = c[g >> 2] | 0;
        if (!e) {
          i = w;
          return;
        }
        j = (-8 - g) | 0;
        m = (a + j) | 0;
        n = (g + p) | 0;
        if (m >>> 0 < h >>> 0) la();
        if ((m | 0) == (c[167] | 0)) {
          g = (a + (p + -4)) | 0;
          f = c[g >> 2] | 0;
          if (((f & 3) | 0) != 3) {
            v = m;
            l = n;
            break;
          }
          c[164] = n;
          c[g >> 2] = f & -2;
          c[(a + (j + 4)) >> 2] = n | 1;
          c[r >> 2] = n;
          i = w;
          return;
        }
        d = g >>> 3;
        if (g >>> 0 < 256) {
          e = c[(a + (j + 8)) >> 2] | 0;
          f = c[(a + (j + 12)) >> 2] | 0;
          g = (688 + ((d << 1) << 2)) | 0;
          if ((e | 0) != (g | 0)) {
            if (e >>> 0 < h >>> 0) la();
            if ((c[(e + 12) >> 2] | 0) != (m | 0)) la();
          }
          if ((f | 0) == (e | 0)) {
            c[162] = c[162] & ~(1 << d);
            v = m;
            l = n;
            break;
          }
          if ((f | 0) != (g | 0)) {
            if (f >>> 0 < h >>> 0) la();
            g = (f + 8) | 0;
            if ((c[g >> 2] | 0) == (m | 0)) b = g;
            else la();
          } else b = (f + 8) | 0;
          c[(e + 12) >> 2] = f;
          c[b >> 2] = e;
          v = m;
          l = n;
          break;
        }
        b = c[(a + (j + 24)) >> 2] | 0;
        e = c[(a + (j + 12)) >> 2] | 0;
        do
          if ((e | 0) == (m | 0)) {
            f = (a + (j + 20)) | 0;
            g = c[f >> 2] | 0;
            if (!g) {
              f = (a + (j + 16)) | 0;
              g = c[f >> 2] | 0;
              if (!g) {
                k = 0;
                break;
              }
            }
            while (1) {
              e = (g + 20) | 0;
              d = c[e >> 2] | 0;
              if (d) {
                g = d;
                f = e;
                continue;
              }
              e = (g + 16) | 0;
              d = c[e >> 2] | 0;
              if (!d) break;
              else {
                g = d;
                f = e;
              }
            }
            if (f >>> 0 < h >>> 0) la();
            else {
              c[f >> 2] = 0;
              k = g;
              break;
            }
          } else {
            d = c[(a + (j + 8)) >> 2] | 0;
            if (d >>> 0 < h >>> 0) la();
            g = (d + 12) | 0;
            if ((c[g >> 2] | 0) != (m | 0)) la();
            f = (e + 8) | 0;
            if ((c[f >> 2] | 0) == (m | 0)) {
              c[g >> 2] = e;
              c[f >> 2] = d;
              k = e;
              break;
            } else la();
          }
        while (0);
        if (b) {
          g = c[(a + (j + 28)) >> 2] | 0;
          f = (952 + (g << 2)) | 0;
          if ((m | 0) == (c[f >> 2] | 0)) {
            c[f >> 2] = k;
            if (!k) {
              c[163] = c[163] & ~(1 << g);
              v = m;
              l = n;
              break;
            }
          } else {
            if (b >>> 0 < (c[166] | 0) >>> 0) la();
            g = (b + 16) | 0;
            if ((c[g >> 2] | 0) == (m | 0)) c[g >> 2] = k;
            else c[(b + 20) >> 2] = k;
            if (!k) {
              v = m;
              l = n;
              break;
            }
          }
          f = c[166] | 0;
          if (k >>> 0 < f >>> 0) la();
          c[(k + 24) >> 2] = b;
          g = c[(a + (j + 16)) >> 2] | 0;
          do
            if (g)
              if (g >>> 0 < f >>> 0) la();
              else {
                c[(k + 16) >> 2] = g;
                c[(g + 24) >> 2] = k;
                break;
              }
          while (0);
          g = c[(a + (j + 20)) >> 2] | 0;
          if (g)
            if (g >>> 0 < (c[166] | 0) >>> 0) la();
            else {
              c[(k + 20) >> 2] = g;
              c[(g + 24) >> 2] = k;
              v = m;
              l = n;
              break;
            }
          else {
            v = m;
            l = n;
          }
        } else {
          v = m;
          l = n;
        }
      } else {
        v = g;
        l = p;
      }
    while (0);
    if (v >>> 0 >= r >>> 0) la();
    g = (a + (p + -4)) | 0;
    f = c[g >> 2] | 0;
    if (!(f & 1)) la();
    if (!(f & 2)) {
      if ((r | 0) == (c[168] | 0)) {
        u = ((c[165] | 0) + l) | 0;
        c[165] = u;
        c[168] = v;
        c[(v + 4) >> 2] = u | 1;
        if ((v | 0) != (c[167] | 0)) {
          i = w;
          return;
        }
        c[167] = 0;
        c[164] = 0;
        i = w;
        return;
      }
      if ((r | 0) == (c[167] | 0)) {
        u = ((c[164] | 0) + l) | 0;
        c[164] = u;
        c[167] = v;
        c[(v + 4) >> 2] = u | 1;
        c[(v + u) >> 2] = u;
        i = w;
        return;
      }
      h = ((f & -8) + l) | 0;
      b = f >>> 3;
      do
        if (f >>> 0 >= 256) {
          b = c[(a + (p + 16)) >> 2] | 0;
          g = c[(a + (p | 4)) >> 2] | 0;
          do
            if ((g | 0) == (r | 0)) {
              f = (a + (p + 12)) | 0;
              g = c[f >> 2] | 0;
              if (!g) {
                f = (a + (p + 8)) | 0;
                g = c[f >> 2] | 0;
                if (!g) {
                  q = 0;
                  break;
                }
              }
              while (1) {
                e = (g + 20) | 0;
                d = c[e >> 2] | 0;
                if (d) {
                  g = d;
                  f = e;
                  continue;
                }
                e = (g + 16) | 0;
                d = c[e >> 2] | 0;
                if (!d) break;
                else {
                  g = d;
                  f = e;
                }
              }
              if (f >>> 0 < (c[166] | 0) >>> 0) la();
              else {
                c[f >> 2] = 0;
                q = g;
                break;
              }
            } else {
              f = c[(a + p) >> 2] | 0;
              if (f >>> 0 < (c[166] | 0) >>> 0) la();
              e = (f + 12) | 0;
              if ((c[e >> 2] | 0) != (r | 0)) la();
              d = (g + 8) | 0;
              if ((c[d >> 2] | 0) == (r | 0)) {
                c[e >> 2] = g;
                c[d >> 2] = f;
                q = g;
                break;
              } else la();
            }
          while (0);
          if (b) {
            g = c[(a + (p + 20)) >> 2] | 0;
            f = (952 + (g << 2)) | 0;
            if ((r | 0) == (c[f >> 2] | 0)) {
              c[f >> 2] = q;
              if (!q) {
                c[163] = c[163] & ~(1 << g);
                break;
              }
            } else {
              if (b >>> 0 < (c[166] | 0) >>> 0) la();
              g = (b + 16) | 0;
              if ((c[g >> 2] | 0) == (r | 0)) c[g >> 2] = q;
              else c[(b + 20) >> 2] = q;
              if (!q) break;
            }
            g = c[166] | 0;
            if (q >>> 0 < g >>> 0) la();
            c[(q + 24) >> 2] = b;
            f = c[(a + (p + 8)) >> 2] | 0;
            do
              if (f)
                if (f >>> 0 < g >>> 0) la();
                else {
                  c[(q + 16) >> 2] = f;
                  c[(f + 24) >> 2] = q;
                  break;
                }
            while (0);
            d = c[(a + (p + 12)) >> 2] | 0;
            if (d)
              if (d >>> 0 < (c[166] | 0) >>> 0) la();
              else {
                c[(q + 20) >> 2] = d;
                c[(d + 24) >> 2] = q;
                break;
              }
          }
        } else {
          d = c[(a + p) >> 2] | 0;
          e = c[(a + (p | 4)) >> 2] | 0;
          g = (688 + ((b << 1) << 2)) | 0;
          if ((d | 0) != (g | 0)) {
            if (d >>> 0 < (c[166] | 0) >>> 0) la();
            if ((c[(d + 12) >> 2] | 0) != (r | 0)) la();
          }
          if ((e | 0) == (d | 0)) {
            c[162] = c[162] & ~(1 << b);
            break;
          }
          if ((e | 0) != (g | 0)) {
            if (e >>> 0 < (c[166] | 0) >>> 0) la();
            f = (e + 8) | 0;
            if ((c[f >> 2] | 0) == (r | 0)) o = f;
            else la();
          } else o = (e + 8) | 0;
          c[(d + 12) >> 2] = e;
          c[o >> 2] = d;
        }
      while (0);
      c[(v + 4) >> 2] = h | 1;
      c[(v + h) >> 2] = h;
      if ((v | 0) == (c[167] | 0)) {
        c[164] = h;
        i = w;
        return;
      } else g = h;
    } else {
      c[g >> 2] = f & -2;
      c[(v + 4) >> 2] = l | 1;
      c[(v + l) >> 2] = l;
      g = l;
    }
    f = g >>> 3;
    if (g >>> 0 < 256) {
      e = f << 1;
      g = (688 + (e << 2)) | 0;
      b = c[162] | 0;
      d = 1 << f;
      if (b & d) {
        d = (688 + ((e + 2) << 2)) | 0;
        b = c[d >> 2] | 0;
        if (b >>> 0 < (c[166] | 0) >>> 0) la();
        else {
          s = d;
          t = b;
        }
      } else {
        c[162] = b | d;
        s = (688 + ((e + 2) << 2)) | 0;
        t = g;
      }
      c[s >> 2] = v;
      c[(t + 12) >> 2] = v;
      c[(v + 8) >> 2] = t;
      c[(v + 12) >> 2] = g;
      i = w;
      return;
    }
    b = g >>> 8;
    if (b)
      if (g >>> 0 > 16777215) f = 31;
      else {
        s = (((b + 1048320) | 0) >>> 16) & 8;
        t = b << s;
        r = (((t + 520192) | 0) >>> 16) & 4;
        t = t << r;
        f = (((t + 245760) | 0) >>> 16) & 2;
        f = (14 - (r | s | f) + ((t << f) >>> 15)) | 0;
        f = ((g >>> ((f + 7) | 0)) & 1) | (f << 1);
      }
    else f = 0;
    d = (952 + (f << 2)) | 0;
    c[(v + 28) >> 2] = f;
    c[(v + 20) >> 2] = 0;
    c[(v + 16) >> 2] = 0;
    b = c[163] | 0;
    e = 1 << f;
    a: do
      if (b & e) {
        e = c[d >> 2] | 0;
        if ((f | 0) == 31) d = 0;
        else d = (25 - (f >>> 1)) | 0;
        b: do
          if (((c[(e + 4) >> 2] & -8) | 0) != (g | 0)) {
            f = g << d;
            while (1) {
              b = (e + ((f >>> 31) << 2) + 16) | 0;
              d = c[b >> 2] | 0;
              if (!d) break;
              if (((c[(d + 4) >> 2] & -8) | 0) == (g | 0)) {
                u = d;
                break b;
              } else {
                f = f << 1;
                e = d;
              }
            }
            if (b >>> 0 < (c[166] | 0) >>> 0) la();
            else {
              c[b >> 2] = v;
              c[(v + 24) >> 2] = e;
              c[(v + 12) >> 2] = v;
              c[(v + 8) >> 2] = v;
              break a;
            }
          } else u = e;
        while (0);
        b = (u + 8) | 0;
        d = c[b >> 2] | 0;
        t = c[166] | 0;
        if ((u >>> 0 >= t >>> 0) & (d >>> 0 >= t >>> 0)) {
          c[(d + 12) >> 2] = v;
          c[b >> 2] = v;
          c[(v + 8) >> 2] = d;
          c[(v + 12) >> 2] = u;
          c[(v + 24) >> 2] = 0;
          break;
        } else la();
      } else {
        c[163] = b | e;
        c[d >> 2] = v;
        c[(v + 24) >> 2] = d;
        c[(v + 12) >> 2] = v;
        c[(v + 8) >> 2] = v;
      }
    while (0);
    v = ((c[170] | 0) + -1) | 0;
    c[170] = v;
    if (!v) b = 1104 | 0;
    else {
      i = w;
      return;
    }
    while (1) {
      b = c[b >> 2] | 0;
      if (!b) break;
      else b = (b + 8) | 0;
    }
    c[170] = -1;
    i = w;
    return;
  }
  function nb() {}
  function ob(a, b, c, d) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    d = d | 0;
    c = (a + c) >>> 0;
    return ((E = (b + d + ((c >>> 0 < a >>> 0) | 0)) >>> 0), c | 0) | 0;
  }
  function pb(b, d, e) {
    b = b | 0;
    d = d | 0;
    e = e | 0;
    var f = 0,
      g = 0,
      h = 0,
      i = 0;
    f = (b + e) | 0;
    if ((e | 0) >= 20) {
      d = d & 255;
      h = b & 3;
      i = d | (d << 8) | (d << 16) | (d << 24);
      g = f & ~3;
      if (h) {
        h = (b + 4 - h) | 0;
        while ((b | 0) < (h | 0)) {
          a[b >> 0] = d;
          b = (b + 1) | 0;
        }
      }
      while ((b | 0) < (g | 0)) {
        c[b >> 2] = i;
        b = (b + 4) | 0;
      }
    }
    while ((b | 0) < (f | 0)) {
      a[b >> 0] = d;
      b = (b + 1) | 0;
    }
    return (b - e) | 0;
  }
  function qb(a, b, c) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    if ((c | 0) < 32) {
      E = b >>> c;
      return (a >>> c) | ((b & ((1 << c) - 1)) << (32 - c));
    }
    E = 0;
    return (b >>> (c - 32)) | 0;
  }
  function rb(a, b, c) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    if ((c | 0) < 32) {
      E = (b << c) | ((a & (((1 << c) - 1) << (32 - c))) >>> (32 - c));
      return a << c;
    }
    E = a << (c - 32);
    return 0;
  }
  function sb(b) {
    b = b | 0;
    var c = 0;
    c = b;
    while (a[c >> 0] | 0) c = (c + 1) | 0;
    return (c - b) | 0;
  }
  function tb(b, d, e) {
    b = b | 0;
    d = d | 0;
    e = e | 0;
    var f = 0;
    if ((e | 0) >= 4096) return sa(b | 0, d | 0, e | 0) | 0;
    f = b | 0;
    if ((b & 3) == (d & 3)) {
      while (b & 3) {
        if (!e) return f | 0;
        a[b >> 0] = a[d >> 0] | 0;
        b = (b + 1) | 0;
        d = (d + 1) | 0;
        e = (e - 1) | 0;
      }
      while ((e | 0) >= 4) {
        c[b >> 2] = c[d >> 2];
        b = (b + 4) | 0;
        d = (d + 4) | 0;
        e = (e - 4) | 0;
      }
    }
    while ((e | 0) > 0) {
      a[b >> 0] = a[d >> 0] | 0;
      b = (b + 1) | 0;
      d = (d + 1) | 0;
      e = (e - 1) | 0;
    }
    return f | 0;
  }
  function ub(a, b, c, d) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    d = d | 0;
    d = (b - d - ((c >>> 0 > a >>> 0) | 0)) >>> 0;
    return ((E = d), ((a - c) >>> 0) | 0) | 0;
  }
  function vb(a, b, c) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    if ((c | 0) < 32) {
      E = b >> c;
      return (a >>> c) | ((b & ((1 << c) - 1)) << (32 - c));
    }
    E = (b | 0) < 0 ? -1 : 0;
    return (b >> (c - 32)) | 0;
  }
  function wb(b) {
    b = b | 0;
    var c = 0;
    c = a[(n + (b >>> 24)) >> 0] | 0;
    if ((c | 0) < 8) return c | 0;
    c = a[(n + ((b >> 16) & 255)) >> 0] | 0;
    if ((c | 0) < 8) return (c + 8) | 0;
    c = a[(n + ((b >> 8) & 255)) >> 0] | 0;
    if ((c | 0) < 8) return (c + 16) | 0;
    return ((a[(n + (b & 255)) >> 0] | 0) + 24) | 0;
  }
  function xb(b) {
    b = b | 0;
    var c = 0;
    c = a[(m + (b & 255)) >> 0] | 0;
    if ((c | 0) < 8) return c | 0;
    c = a[(m + ((b >> 8) & 255)) >> 0] | 0;
    if ((c | 0) < 8) return (c + 8) | 0;
    c = a[(m + ((b >> 16) & 255)) >> 0] | 0;
    if ((c | 0) < 8) return (c + 16) | 0;
    return ((a[(m + (b >>> 24)) >> 0] | 0) + 24) | 0;
  }
  function yb(a, b) {
    a = a | 0;
    b = b | 0;
    var c = 0,
      d = 0,
      e = 0,
      f = 0;
    f = a & 65535;
    e = b & 65535;
    c = aa(e, f) | 0;
    d = a >>> 16;
    a = ((c >>> 16) + (aa(e, d) | 0)) | 0;
    e = b >>> 16;
    b = aa(e, f) | 0;
    return (
      ((E =
        ((a >>> 16) + (aa(e, d) | 0) + ((((a & 65535) + b) | 0) >>> 16)) | 0),
      ((a + b) << 16) | (c & 65535) | 0) | 0
    );
  }
  function zb(a, b, c, d) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    d = d | 0;
    var e = 0,
      f = 0,
      g = 0,
      h = 0,
      i = 0,
      j = 0;
    j = (b >> 31) | (((b | 0) < 0 ? -1 : 0) << 1);
    i = (((b | 0) < 0 ? -1 : 0) >> 31) | (((b | 0) < 0 ? -1 : 0) << 1);
    f = (d >> 31) | (((d | 0) < 0 ? -1 : 0) << 1);
    e = (((d | 0) < 0 ? -1 : 0) >> 31) | (((d | 0) < 0 ? -1 : 0) << 1);
    h = ub(j ^ a, i ^ b, j, i) | 0;
    g = E;
    a = f ^ j;
    b = e ^ i;
    d =
      ub((Eb(h, g, ub(f ^ c, e ^ d, f, e) | 0, E, 0) | 0) ^ a, E ^ b, a, b) | 0;
    return d | 0;
  }
  function Ab(a, b, d, e) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    e = e | 0;
    var f = 0,
      g = 0,
      h = 0,
      j = 0,
      k = 0,
      l = 0;
    f = i;
    i = (i + 8) | 0;
    j = f | 0;
    h = (b >> 31) | (((b | 0) < 0 ? -1 : 0) << 1);
    g = (((b | 0) < 0 ? -1 : 0) >> 31) | (((b | 0) < 0 ? -1 : 0) << 1);
    l = (e >> 31) | (((e | 0) < 0 ? -1 : 0) << 1);
    k = (((e | 0) < 0 ? -1 : 0) >> 31) | (((e | 0) < 0 ? -1 : 0) << 1);
    a = ub(h ^ a, g ^ b, h, g) | 0;
    b = E;
    Eb(a, b, ub(l ^ d, k ^ e, l, k) | 0, E, j) | 0;
    e = ub(c[j >> 2] ^ h, c[(j + 4) >> 2] ^ g, h, g) | 0;
    d = E;
    i = f;
    return ((E = d), e) | 0;
  }
  function Bb(a, b, c, d) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    d = d | 0;
    var e = 0,
      f = 0;
    e = a;
    f = c;
    c = yb(e, f) | 0;
    a = E;
    return (
      ((E = ((aa(b, f) | 0) + (aa(d, e) | 0) + a) | (a & 0)), c | 0 | 0) | 0
    );
  }
  function Cb(a, b, c, d) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    d = d | 0;
    d = Eb(a, b, c, d, 0) | 0;
    return d | 0;
  }
  function Db(a, b, d, e) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    e = e | 0;
    var f = 0,
      g = 0;
    g = i;
    i = (i + 8) | 0;
    f = g | 0;
    Eb(a, b, d, e, f) | 0;
    i = g;
    return ((E = c[(f + 4) >> 2] | 0), c[f >> 2] | 0) | 0;
  }
  function Eb(a, b, d, e, f) {
    a = a | 0;
    b = b | 0;
    d = d | 0;
    e = e | 0;
    f = f | 0;
    var g = 0,
      h = 0,
      i = 0,
      j = 0,
      k = 0,
      l = 0,
      m = 0,
      n = 0,
      o = 0,
      p = 0;
    n = a;
    l = b;
    m = l;
    k = d;
    o = e;
    i = o;
    if (!m) {
      g = (f | 0) != 0;
      if (!i) {
        if (g) {
          c[f >> 2] = (n >>> 0) % (k >>> 0);
          c[(f + 4) >> 2] = 0;
        }
        o = 0;
        f = ((n >>> 0) / (k >>> 0)) >>> 0;
        return ((E = o), f) | 0;
      } else {
        if (!g) {
          o = 0;
          f = 0;
          return ((E = o), f) | 0;
        }
        c[f >> 2] = a | 0;
        c[(f + 4) >> 2] = b & 0;
        o = 0;
        f = 0;
        return ((E = o), f) | 0;
      }
    }
    j = (i | 0) == 0;
    do
      if (k) {
        if (!j) {
          h = ((wb(i | 0) | 0) - (wb(m | 0) | 0)) | 0;
          if (h >>> 0 <= 31) {
            g = (h + 1) | 0;
            l = (31 - h) | 0;
            k = (h - 31) >> 31;
            i = g;
            j = ((n >>> (g >>> 0)) & k) | (m << l);
            k = (m >>> (g >>> 0)) & k;
            g = 0;
            h = n << l;
            break;
          }
          if (!f) {
            o = 0;
            f = 0;
            return ((E = o), f) | 0;
          }
          c[f >> 2] = a | 0;
          c[(f + 4) >> 2] = l | (b & 0);
          o = 0;
          f = 0;
          return ((E = o), f) | 0;
        }
        j = (k - 1) | 0;
        if (j & k) {
          h = ((wb(k | 0) | 0) + 33 - (wb(m | 0) | 0)) | 0;
          p = (64 - h) | 0;
          l = (32 - h) | 0;
          a = l >> 31;
          b = (h - 32) | 0;
          k = b >> 31;
          i = h;
          j =
            (((l - 1) >> 31) & (m >>> (b >>> 0))) |
            (((m << l) | (n >>> (h >>> 0))) & k);
          k = k & (m >>> (h >>> 0));
          g = (n << p) & a;
          h =
            (((m << p) | (n >>> (b >>> 0))) & a) |
            ((n << l) & ((h - 33) >> 31));
          break;
        }
        if (f) {
          c[f >> 2] = j & n;
          c[(f + 4) >> 2] = 0;
        }
        if ((k | 0) == 1) {
          f = l | (b & 0);
          p = a | 0 | 0;
          return ((E = f), p) | 0;
        } else {
          p = xb(k | 0) | 0;
          f = (m >>> (p >>> 0)) | 0;
          p = (m << (32 - p)) | (n >>> (p >>> 0)) | 0;
          return ((E = f), p) | 0;
        }
      } else {
        if (j) {
          if (f) {
            c[f >> 2] = (m >>> 0) % (k >>> 0);
            c[(f + 4) >> 2] = 0;
          }
          f = 0;
          p = ((m >>> 0) / (k >>> 0)) >>> 0;
          return ((E = f), p) | 0;
        }
        if (!n) {
          if (f) {
            c[f >> 2] = 0;
            c[(f + 4) >> 2] = (m >>> 0) % (i >>> 0);
          }
          f = 0;
          p = ((m >>> 0) / (i >>> 0)) >>> 0;
          return ((E = f), p) | 0;
        }
        j = (i - 1) | 0;
        if (!(j & i)) {
          if (f) {
            c[f >> 2] = a | 0;
            c[(f + 4) >> 2] = (j & m) | (b & 0);
          }
          f = 0;
          p = m >>> ((xb(i | 0) | 0) >>> 0);
          return ((E = f), p) | 0;
        }
        h = ((wb(i | 0) | 0) - (wb(m | 0) | 0)) | 0;
        if (h >>> 0 <= 30) {
          k = (h + 1) | 0;
          h = (31 - h) | 0;
          i = k;
          j = (m << h) | (n >>> (k >>> 0));
          k = m >>> (k >>> 0);
          g = 0;
          h = n << h;
          break;
        }
        if (!f) {
          f = 0;
          p = 0;
          return ((E = f), p) | 0;
        }
        c[f >> 2] = a | 0;
        c[(f + 4) >> 2] = l | (b & 0);
        f = 0;
        p = 0;
        return ((E = f), p) | 0;
      }
    while (0);
    if (!i) {
      l = h;
      i = 0;
      h = 0;
    } else {
      m = d | 0 | 0;
      l = o | (e & 0);
      b = ob(m, l, -1, -1) | 0;
      a = E;
      d = h;
      h = 0;
      do {
        n = d;
        d = (g >>> 31) | (d << 1);
        g = h | (g << 1);
        n = (j << 1) | (n >>> 31) | 0;
        e = (j >>> 31) | (k << 1) | 0;
        ub(b, a, n, e) | 0;
        p = E;
        o = (p >> 31) | (((p | 0) < 0 ? -1 : 0) << 1);
        h = o & 1;
        j =
          ub(
            n,
            e,
            o & m,
            ((((p | 0) < 0 ? -1 : 0) >> 31) | (((p | 0) < 0 ? -1 : 0) << 1)) & l
          ) | 0;
        k = E;
        i = (i - 1) | 0;
      } while ((i | 0) != 0);
      l = d;
      i = 0;
    }
    d = 0;
    if (f) {
      c[f >> 2] = j;
      c[(f + 4) >> 2] = k;
    }
    f = ((g | 0) >>> 31) | ((l | d) << 1) | (((d << 1) | (g >>> 31)) & 0) | i;
    p = (((g << 1) | (0 >>> 31)) & -2) | h;
    return ((E = f), p) | 0;
  }
  function Fb(a, b, c, d, e, f) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    d = d | 0;
    e = e | 0;
    f = f | 0;
    return za[a & 1](b | 0, c | 0, d | 0, e | 0, f | 0) | 0;
  }
  function Gb(a, b, c, d, e) {
    a = a | 0;
    b = b | 0;
    c = c | 0;
    d = d | 0;
    e = e | 0;
    ba(0);
    return 0;
  }

  // EMSCRIPTEN_END_FUNCS
  var za = [Gb, Ka];
  return {
    _strlen: sb,
    _free: mb,
    _i64Add: ob,
    _secp256k1_start: Ia,
    _memset: pb,
    _malloc: lb,
    _secp256k1_ecdsa_sign: La,
    _memcpy: tb,
    _bitshift64Lshr: qb,
    _bitshift64Shl: rb,
    _secp256k1_ec_pubkey_create: Oa,
    runPostSets: nb,
    stackAlloc: Aa,
    stackSave: Ba,
    stackRestore: Ca,
    setThrew: Da,
    setTempRet0: Ga,
    getTempRet0: Ha,
    dynCall_iiiiii: Fb,
  };
})(
  // EMSCRIPTEN_END_ASM
  Module.asmGlobalArg,
  Module.asmLibraryArg,
  buffer
);
var _strlen = (Module["_strlen"] = asm["_strlen"]);
var _free = (Module["_free"] = asm["_free"]);
var _i64Add = (Module["_i64Add"] = asm["_i64Add"]);
var _secp256k1_start = (Module["_secp256k1_start"] = asm["_secp256k1_start"]);
var _memset = (Module["_memset"] = asm["_memset"]);
var _malloc = (Module["_malloc"] = asm["_malloc"]);
var _secp256k1_ecdsa_sign = (Module["_secp256k1_ecdsa_sign"] =
  asm["_secp256k1_ecdsa_sign"]);
var _memcpy = (Module["_memcpy"] = asm["_memcpy"]);
var _bitshift64Lshr = (Module["_bitshift64Lshr"] = asm["_bitshift64Lshr"]);
var _bitshift64Shl = (Module["_bitshift64Shl"] = asm["_bitshift64Shl"]);
var _secp256k1_ec_pubkey_create = (Module["_secp256k1_ec_pubkey_create"] =
  asm["_secp256k1_ec_pubkey_create"]);
var runPostSets = (Module["runPostSets"] = asm["runPostSets"]);
var dynCall_iiiiii = (Module["dynCall_iiiiii"] = asm["dynCall_iiiiii"]);
Runtime.stackAlloc = asm["stackAlloc"];
Runtime.stackSave = asm["stackSave"];
Runtime.stackRestore = asm["stackRestore"];
Runtime.setTempRet0 = asm["setTempRet0"];
Runtime.getTempRet0 = asm["getTempRet0"];
var i64Math = (function () {
  var goog = { math: {} };
  goog.math.Long = function (low, high) {
    this.low_ = low | 0;
    this.high_ = high | 0;
  };
  goog.math.Long.IntCache_ = {};
  goog.math.Long.fromInt = function (value) {
    if (-128 <= value && value < 128) {
      var cachedObj = goog.math.Long.IntCache_[value];
      if (cachedObj) {
        return cachedObj;
      }
    }
    var obj = new goog.math.Long(value | 0, value < 0 ? -1 : 0);
    if (-128 <= value && value < 128) {
      goog.math.Long.IntCache_[value] = obj;
    }
    return obj;
  };
  goog.math.Long.fromNumber = function (value) {
    if (isNaN(value) || !isFinite(value)) {
      return goog.math.Long.ZERO;
    } else if (value <= -goog.math.Long.TWO_PWR_63_DBL_) {
      return goog.math.Long.MIN_VALUE;
    } else if (value + 1 >= goog.math.Long.TWO_PWR_63_DBL_) {
      return goog.math.Long.MAX_VALUE;
    } else if (value < 0) {
      return goog.math.Long.fromNumber(-value).negate();
    } else {
      return new goog.math.Long(
        value % goog.math.Long.TWO_PWR_32_DBL_ | 0,
        (value / goog.math.Long.TWO_PWR_32_DBL_) | 0
      );
    }
  };
  goog.math.Long.fromBits = function (lowBits, highBits) {
    return new goog.math.Long(lowBits, highBits);
  };
  goog.math.Long.fromString = function (str, opt_radix) {
    if (str.length == 0) {
      throw Error("number format error: empty string");
    }
    var radix = opt_radix || 10;
    if (radix < 2 || 36 < radix) {
      throw Error("radix out of range: " + radix);
    }
    if (str.charAt(0) == "-") {
      return goog.math.Long.fromString(str.substring(1), radix).negate();
    } else if (str.indexOf("-") >= 0) {
      throw Error('number format error: interior "-" character: ' + str);
    }
    var radixToPower = goog.math.Long.fromNumber(Math.pow(radix, 8));
    var result = goog.math.Long.ZERO;
    for (var i = 0; i < str.length; i += 8) {
      var size = Math.min(8, str.length - i);
      var value = parseInt(str.substring(i, i + size), radix);
      if (size < 8) {
        var power = goog.math.Long.fromNumber(Math.pow(radix, size));
        result = result.multiply(power).add(goog.math.Long.fromNumber(value));
      } else {
        result = result.multiply(radixToPower);
        result = result.add(goog.math.Long.fromNumber(value));
      }
    }
    return result;
  };
  goog.math.Long.TWO_PWR_16_DBL_ = 1 << 16;
  goog.math.Long.TWO_PWR_24_DBL_ = 1 << 24;
  goog.math.Long.TWO_PWR_32_DBL_ =
    goog.math.Long.TWO_PWR_16_DBL_ * goog.math.Long.TWO_PWR_16_DBL_;
  goog.math.Long.TWO_PWR_31_DBL_ = goog.math.Long.TWO_PWR_32_DBL_ / 2;
  goog.math.Long.TWO_PWR_48_DBL_ =
    goog.math.Long.TWO_PWR_32_DBL_ * goog.math.Long.TWO_PWR_16_DBL_;
  goog.math.Long.TWO_PWR_64_DBL_ =
    goog.math.Long.TWO_PWR_32_DBL_ * goog.math.Long.TWO_PWR_32_DBL_;
  goog.math.Long.TWO_PWR_63_DBL_ = goog.math.Long.TWO_PWR_64_DBL_ / 2;
  goog.math.Long.ZERO = goog.math.Long.fromInt(0);
  goog.math.Long.ONE = goog.math.Long.fromInt(1);
  goog.math.Long.NEG_ONE = goog.math.Long.fromInt(-1);
  goog.math.Long.MAX_VALUE = goog.math.Long.fromBits(
    4294967295 | 0,
    2147483647 | 0
  );
  goog.math.Long.MIN_VALUE = goog.math.Long.fromBits(0, 2147483648 | 0);
  goog.math.Long.TWO_PWR_24_ = goog.math.Long.fromInt(1 << 24);
  goog.math.Long.prototype.toInt = function () {
    return this.low_;
  };
  goog.math.Long.prototype.toNumber = function () {
    return (
      this.high_ * goog.math.Long.TWO_PWR_32_DBL_ + this.getLowBitsUnsigned()
    );
  };
  goog.math.Long.prototype.toString = function (opt_radix) {
    var radix = opt_radix || 10;
    if (radix < 2 || 36 < radix) {
      throw Error("radix out of range: " + radix);
    }
    if (this.isZero()) {
      return "0";
    }
    if (this.isNegative()) {
      if (this.equals(goog.math.Long.MIN_VALUE)) {
        var radixLong = goog.math.Long.fromNumber(radix);
        var div = this.div(radixLong);
        var rem = div.multiply(radixLong).subtract(this);
        return div.toString(radix) + rem.toInt().toString(radix);
      } else {
        return "-" + this.negate().toString(radix);
      }
    }
    var radixToPower = goog.math.Long.fromNumber(Math.pow(radix, 6));
    var rem = this;
    var result = "";
    while (true) {
      var remDiv = rem.div(radixToPower);
      var intval = rem.subtract(remDiv.multiply(radixToPower)).toInt();
      var digits = intval.toString(radix);
      rem = remDiv;
      if (rem.isZero()) {
        return digits + result;
      } else {
        while (digits.length < 6) {
          digits = "0" + digits;
        }
        result = "" + digits + result;
      }
    }
  };
  goog.math.Long.prototype.getHighBits = function () {
    return this.high_;
  };
  goog.math.Long.prototype.getLowBits = function () {
    return this.low_;
  };
  goog.math.Long.prototype.getLowBitsUnsigned = function () {
    return this.low_ >= 0
      ? this.low_
      : goog.math.Long.TWO_PWR_32_DBL_ + this.low_;
  };
  goog.math.Long.prototype.getNumBitsAbs = function () {
    if (this.isNegative()) {
      if (this.equals(goog.math.Long.MIN_VALUE)) {
        return 64;
      } else {
        return this.negate().getNumBitsAbs();
      }
    } else {
      var val = this.high_ != 0 ? this.high_ : this.low_;
      for (var bit = 31; bit > 0; bit--) {
        if ((val & (1 << bit)) != 0) {
          break;
        }
      }
      return this.high_ != 0 ? bit + 33 : bit + 1;
    }
  };
  goog.math.Long.prototype.isZero = function () {
    return this.high_ == 0 && this.low_ == 0;
  };
  goog.math.Long.prototype.isNegative = function () {
    return this.high_ < 0;
  };
  goog.math.Long.prototype.isOdd = function () {
    return (this.low_ & 1) == 1;
  };
  goog.math.Long.prototype.equals = function (other) {
    return this.high_ == other.high_ && this.low_ == other.low_;
  };
  goog.math.Long.prototype.notEquals = function (other) {
    return this.high_ != other.high_ || this.low_ != other.low_;
  };
  goog.math.Long.prototype.lessThan = function (other) {
    return this.compare(other) < 0;
  };
  goog.math.Long.prototype.lessThanOrEqual = function (other) {
    return this.compare(other) <= 0;
  };
  goog.math.Long.prototype.greaterThan = function (other) {
    return this.compare(other) > 0;
  };
  goog.math.Long.prototype.greaterThanOrEqual = function (other) {
    return this.compare(other) >= 0;
  };
  goog.math.Long.prototype.compare = function (other) {
    if (this.equals(other)) {
      return 0;
    }
    var thisNeg = this.isNegative();
    var otherNeg = other.isNegative();
    if (thisNeg && !otherNeg) {
      return -1;
    }
    if (!thisNeg && otherNeg) {
      return 1;
    }
    if (this.subtract(other).isNegative()) {
      return -1;
    } else {
      return 1;
    }
  };
  goog.math.Long.prototype.negate = function () {
    if (this.equals(goog.math.Long.MIN_VALUE)) {
      return goog.math.Long.MIN_VALUE;
    } else {
      return this.not().add(goog.math.Long.ONE);
    }
  };
  goog.math.Long.prototype.add = function (other) {
    var a48 = this.high_ >>> 16;
    var a32 = this.high_ & 65535;
    var a16 = this.low_ >>> 16;
    var a00 = this.low_ & 65535;
    var b48 = other.high_ >>> 16;
    var b32 = other.high_ & 65535;
    var b16 = other.low_ >>> 16;
    var b00 = other.low_ & 65535;
    var c48 = 0,
      c32 = 0,
      c16 = 0,
      c00 = 0;
    c00 += a00 + b00;
    c16 += c00 >>> 16;
    c00 &= 65535;
    c16 += a16 + b16;
    c32 += c16 >>> 16;
    c16 &= 65535;
    c32 += a32 + b32;
    c48 += c32 >>> 16;
    c32 &= 65535;
    c48 += a48 + b48;
    c48 &= 65535;
    return goog.math.Long.fromBits((c16 << 16) | c00, (c48 << 16) | c32);
  };
  goog.math.Long.prototype.subtract = function (other) {
    return this.add(other.negate());
  };
  goog.math.Long.prototype.multiply = function (other) {
    if (this.isZero()) {
      return goog.math.Long.ZERO;
    } else if (other.isZero()) {
      return goog.math.Long.ZERO;
    }
    if (this.equals(goog.math.Long.MIN_VALUE)) {
      return other.isOdd() ? goog.math.Long.MIN_VALUE : goog.math.Long.ZERO;
    } else if (other.equals(goog.math.Long.MIN_VALUE)) {
      return this.isOdd() ? goog.math.Long.MIN_VALUE : goog.math.Long.ZERO;
    }
    if (this.isNegative()) {
      if (other.isNegative()) {
        return this.negate().multiply(other.negate());
      } else {
        return this.negate().multiply(other).negate();
      }
    } else if (other.isNegative()) {
      return this.multiply(other.negate()).negate();
    }
    if (
      this.lessThan(goog.math.Long.TWO_PWR_24_) &&
      other.lessThan(goog.math.Long.TWO_PWR_24_)
    ) {
      return goog.math.Long.fromNumber(this.toNumber() * other.toNumber());
    }
    var a48 = this.high_ >>> 16;
    var a32 = this.high_ & 65535;
    var a16 = this.low_ >>> 16;
    var a00 = this.low_ & 65535;
    var b48 = other.high_ >>> 16;
    var b32 = other.high_ & 65535;
    var b16 = other.low_ >>> 16;
    var b00 = other.low_ & 65535;
    var c48 = 0,
      c32 = 0,
      c16 = 0,
      c00 = 0;
    c00 += a00 * b00;
    c16 += c00 >>> 16;
    c00 &= 65535;
    c16 += a16 * b00;
    c32 += c16 >>> 16;
    c16 &= 65535;
    c16 += a00 * b16;
    c32 += c16 >>> 16;
    c16 &= 65535;
    c32 += a32 * b00;
    c48 += c32 >>> 16;
    c32 &= 65535;
    c32 += a16 * b16;
    c48 += c32 >>> 16;
    c32 &= 65535;
    c32 += a00 * b32;
    c48 += c32 >>> 16;
    c32 &= 65535;
    c48 += a48 * b00 + a32 * b16 + a16 * b32 + a00 * b48;
    c48 &= 65535;
    return goog.math.Long.fromBits((c16 << 16) | c00, (c48 << 16) | c32);
  };
  goog.math.Long.prototype.div = function (other) {
    if (other.isZero()) {
      throw Error("division by zero");
    } else if (this.isZero()) {
      return goog.math.Long.ZERO;
    }
    if (this.equals(goog.math.Long.MIN_VALUE)) {
      if (
        other.equals(goog.math.Long.ONE) ||
        other.equals(goog.math.Long.NEG_ONE)
      ) {
        return goog.math.Long.MIN_VALUE;
      } else if (other.equals(goog.math.Long.MIN_VALUE)) {
        return goog.math.Long.ONE;
      } else {
        var halfThis = this.shiftRight(1);
        var approx = halfThis.div(other).shiftLeft(1);
        if (approx.equals(goog.math.Long.ZERO)) {
          return other.isNegative()
            ? goog.math.Long.ONE
            : goog.math.Long.NEG_ONE;
        } else {
          var rem = this.subtract(other.multiply(approx));
          var result = approx.add(rem.div(other));
          return result;
        }
      }
    } else if (other.equals(goog.math.Long.MIN_VALUE)) {
      return goog.math.Long.ZERO;
    }
    if (this.isNegative()) {
      if (other.isNegative()) {
        return this.negate().div(other.negate());
      } else {
        return this.negate().div(other).negate();
      }
    } else if (other.isNegative()) {
      return this.div(other.negate()).negate();
    }
    var res = goog.math.Long.ZERO;
    var rem = this;
    while (rem.greaterThanOrEqual(other)) {
      var approx = Math.max(1, Math.floor(rem.toNumber() / other.toNumber()));
      var log2 = Math.ceil(Math.log(approx) / Math.LN2);
      var delta = log2 <= 48 ? 1 : Math.pow(2, log2 - 48);
      var approxRes = goog.math.Long.fromNumber(approx);
      var approxRem = approxRes.multiply(other);
      while (approxRem.isNegative() || approxRem.greaterThan(rem)) {
        approx -= delta;
        approxRes = goog.math.Long.fromNumber(approx);
        approxRem = approxRes.multiply(other);
      }
      if (approxRes.isZero()) {
        approxRes = goog.math.Long.ONE;
      }
      res = res.add(approxRes);
      rem = rem.subtract(approxRem);
    }
    return res;
  };
  goog.math.Long.prototype.modulo = function (other) {
    return this.subtract(this.div(other).multiply(other));
  };
  goog.math.Long.prototype.not = function () {
    return goog.math.Long.fromBits(~this.low_, ~this.high_);
  };
  goog.math.Long.prototype.and = function (other) {
    return goog.math.Long.fromBits(
      this.low_ & other.low_,
      this.high_ & other.high_
    );
  };
  goog.math.Long.prototype.or = function (other) {
    return goog.math.Long.fromBits(
      this.low_ | other.low_,
      this.high_ | other.high_
    );
  };
  goog.math.Long.prototype.xor = function (other) {
    return goog.math.Long.fromBits(
      this.low_ ^ other.low_,
      this.high_ ^ other.high_
    );
  };
  goog.math.Long.prototype.shiftLeft = function (numBits) {
    numBits &= 63;
    if (numBits == 0) {
      return this;
    } else {
      var low = this.low_;
      if (numBits < 32) {
        var high = this.high_;
        return goog.math.Long.fromBits(
          low << numBits,
          (high << numBits) | (low >>> (32 - numBits))
        );
      } else {
        return goog.math.Long.fromBits(0, low << (numBits - 32));
      }
    }
  };
  goog.math.Long.prototype.shiftRight = function (numBits) {
    numBits &= 63;
    if (numBits == 0) {
      return this;
    } else {
      var high = this.high_;
      if (numBits < 32) {
        var low = this.low_;
        return goog.math.Long.fromBits(
          (low >>> numBits) | (high << (32 - numBits)),
          high >> numBits
        );
      } else {
        return goog.math.Long.fromBits(
          high >> (numBits - 32),
          high >= 0 ? 0 : -1
        );
      }
    }
  };
  goog.math.Long.prototype.shiftRightUnsigned = function (numBits) {
    numBits &= 63;
    if (numBits == 0) {
      return this;
    } else {
      var high = this.high_;
      if (numBits < 32) {
        var low = this.low_;
        return goog.math.Long.fromBits(
          (low >>> numBits) | (high << (32 - numBits)),
          high >>> numBits
        );
      } else if (numBits == 32) {
        return goog.math.Long.fromBits(high, 0);
      } else {
        return goog.math.Long.fromBits(high >>> (numBits - 32), 0);
      }
    }
  };
  var navigator = { appName: "Modern Browser" };
  var dbits;
  var canary = 0xdeadbeefcafe;
  var j_lm = (canary & 16777215) == 15715070;
  function BigInteger(a, b, c) {
    if (a != null)
      if ("number" == typeof a) this.fromNumber(a, b, c);
      else if (b == null && "string" != typeof a) this.fromString(a, 256);
      else this.fromString(a, b);
  }
  function nbi() {
    return new BigInteger(null);
  }
  function am1(i, x, w, j, c, n) {
    while (--n >= 0) {
      var v = x * this[i++] + w[j] + c;
      c = Math.floor(v / 67108864);
      w[j++] = v & 67108863;
    }
    return c;
  }
  function am2(i, x, w, j, c, n) {
    var xl = x & 32767,
      xh = x >> 15;
    while (--n >= 0) {
      var l = this[i] & 32767;
      var h = this[i++] >> 15;
      var m = xh * l + h * xl;
      l = xl * l + ((m & 32767) << 15) + w[j] + (c & 1073741823);
      c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
      w[j++] = l & 1073741823;
    }
    return c;
  }
  function am3(i, x, w, j, c, n) {
    var xl = x & 16383,
      xh = x >> 14;
    while (--n >= 0) {
      var l = this[i] & 16383;
      var h = this[i++] >> 14;
      var m = xh * l + h * xl;
      l = xl * l + ((m & 16383) << 14) + w[j] + c;
      c = (l >> 28) + (m >> 14) + xh * h;
      w[j++] = l & 268435455;
    }
    return c;
  }
  if (j_lm && navigator.appName == "Microsoft Internet Explorer") {
    BigInteger.prototype.am = am2;
    dbits = 30;
  } else if (j_lm && navigator.appName != "Netscape") {
    BigInteger.prototype.am = am1;
    dbits = 26;
  } else {
    BigInteger.prototype.am = am3;
    dbits = 28;
  }
  BigInteger.prototype.DB = dbits;
  BigInteger.prototype.DM = (1 << dbits) - 1;
  BigInteger.prototype.DV = 1 << dbits;
  var BI_FP = 52;
  BigInteger.prototype.FV = Math.pow(2, BI_FP);
  BigInteger.prototype.F1 = BI_FP - dbits;
  BigInteger.prototype.F2 = 2 * dbits - BI_FP;
  var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
  var BI_RC = new Array();
  var rr, vv;
  rr = "0".charCodeAt(0);
  for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
  rr = "a".charCodeAt(0);
  for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
  rr = "A".charCodeAt(0);
  for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
  function int2char(n) {
    return BI_RM.charAt(n);
  }
  function intAt(s, i) {
    var c = BI_RC[s.charCodeAt(i)];
    return c == null ? -1 : c;
  }
  function bnpCopyTo(r) {
    for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
    r.t = this.t;
    r.s = this.s;
  }
  function bnpFromInt(x) {
    this.t = 1;
    this.s = x < 0 ? -1 : 0;
    if (x > 0) this[0] = x;
    else if (x < -1) this[0] = x + DV;
    else this.t = 0;
  }
  function nbv(i) {
    var r = nbi();
    r.fromInt(i);
    return r;
  }
  function bnpFromString(s, b) {
    var k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 256) k = 8;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else {
      this.fromRadix(s, b);
      return;
    }
    this.t = 0;
    this.s = 0;
    var i = s.length,
      mi = false,
      sh = 0;
    while (--i >= 0) {
      var x = k == 8 ? s[i] & 255 : intAt(s, i);
      if (x < 0) {
        if (s.charAt(i) == "-") mi = true;
        continue;
      }
      mi = false;
      if (sh == 0) this[this.t++] = x;
      else if (sh + k > this.DB) {
        this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
        this[this.t++] = x >> (this.DB - sh);
      } else this[this.t - 1] |= x << sh;
      sh += k;
      if (sh >= this.DB) sh -= this.DB;
    }
    if (k == 8 && (s[0] & 128) != 0) {
      this.s = -1;
      if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
    }
    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
  }
  function bnpClamp() {
    var c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == c) --this.t;
  }
  function bnToString(b) {
    if (this.s < 0) return "-" + this.negate().toString(b);
    var k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else return this.toRadix(b);
    var km = (1 << k) - 1,
      d,
      m = false,
      r = "",
      i = this.t;
    var p = this.DB - ((i * this.DB) % k);
    if (i-- > 0) {
      if (p < this.DB && (d = this[i] >> p) > 0) {
        m = true;
        r = int2char(d);
      }
      while (i >= 0) {
        if (p < k) {
          d = (this[i] & ((1 << p) - 1)) << (k - p);
          d |= this[--i] >> (p += this.DB - k);
        } else {
          d = (this[i] >> (p -= k)) & km;
          if (p <= 0) {
            p += this.DB;
            --i;
          }
        }
        if (d > 0) m = true;
        if (m) r += int2char(d);
      }
    }
    return m ? r : "0";
  }
  function bnNegate() {
    var r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
  }
  function bnAbs() {
    return this.s < 0 ? this.negate() : this;
  }
  function bnCompareTo(a) {
    var r = this.s - a.s;
    if (r != 0) return r;
    var i = this.t;
    r = i - a.t;
    if (r != 0) return this.s < 0 ? -r : r;
    while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
    return 0;
  }
  function nbits(x) {
    var r = 1,
      t;
    if ((t = x >>> 16) != 0) {
      x = t;
      r += 16;
    }
    if ((t = x >> 8) != 0) {
      x = t;
      r += 8;
    }
    if ((t = x >> 4) != 0) {
      x = t;
      r += 4;
    }
    if ((t = x >> 2) != 0) {
      x = t;
      r += 2;
    }
    if ((t = x >> 1) != 0) {
      x = t;
      r += 1;
    }
    return r;
  }
  function bnBitLength() {
    if (this.t <= 0) return 0;
    return (
      this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM))
    );
  }
  function bnpDLShiftTo(n, r) {
    var i;
    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
    for (i = n - 1; i >= 0; --i) r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
  }
  function bnpDRShiftTo(n, r) {
    for (var i = n; i < this.t; ++i) r[i - n] = this[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
  }
  function bnpLShiftTo(n, r) {
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << cbs) - 1;
    var ds = Math.floor(n / this.DB),
      c = (this.s << bs) & this.DM,
      i;
    for (i = this.t - 1; i >= 0; --i) {
      r[i + ds + 1] = (this[i] >> cbs) | c;
      c = (this[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
  }
  function bnpRShiftTo(n, r) {
    r.s = this.s;
    var ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
      r.t = 0;
      return;
    }
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << bs) - 1;
    r[0] = this[ds] >> bs;
    for (var i = ds + 1; i < this.t; ++i) {
      r[i - ds - 1] |= (this[i] & bm) << cbs;
      r[i - ds] = this[i] >> bs;
    }
    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
  }
  function bnpSubTo(a, r) {
    var i = 0,
      c = 0,
      m = Math.min(a.t, this.t);
    while (i < m) {
      c += this[i] - a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c -= a.s;
      while (i < this.t) {
        c += this[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c -= a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c -= a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c < -1) r[i++] = this.DV + c;
    else if (c > 0) r[i++] = c;
    r.t = i;
    r.clamp();
  }
  function bnpMultiplyTo(a, r) {
    var x = this.abs(),
      y = a.abs();
    var i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
  }
  function bnpSquareTo(r) {
    var x = this.abs();
    var i = (r.t = 2 * x.t);
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
      var c = x.am(i, x[i], r, 2 * i, 0, 1);
      if (
        (r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >=
        x.DV
      ) {
        r[i + x.t] -= x.DV;
        r[i + x.t + 1] = 1;
      }
    }
    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
  }
  function bnpDivRemTo(m, q, r) {
    var pm = m.abs();
    if (pm.t <= 0) return;
    var pt = this.abs();
    if (pt.t < pm.t) {
      if (q != null) q.fromInt(0);
      if (r != null) this.copyTo(r);
      return;
    }
    if (r == null) r = nbi();
    var y = nbi(),
      ts = this.s,
      ms = m.s;
    var nsh = this.DB - nbits(pm[pm.t - 1]);
    if (nsh > 0) {
      pm.lShiftTo(nsh, y);
      pt.lShiftTo(nsh, r);
    } else {
      pm.copyTo(y);
      pt.copyTo(r);
    }
    var ys = y.t;
    var y0 = y[ys - 1];
    if (y0 == 0) return;
    var yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2] >> this.F2 : 0);
    var d1 = this.FV / yt,
      d2 = (1 << this.F1) / yt,
      e = 1 << this.F2;
    var i = r.t,
      j = i - ys,
      t = q == null ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
      r[r.t++] = 1;
      r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y);
    while (y.t < ys) y[y.t++] = 0;
    while (--j >= 0) {
      var qd =
        r[--i] == y0 ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
      if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
        y.dlShiftTo(j, t);
        r.subTo(t, r);
        while (r[i] < --qd) r.subTo(t, r);
      }
    }
    if (q != null) {
      r.drShiftTo(ys, q);
      if (ts != ms) BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r);
    if (ts < 0) BigInteger.ZERO.subTo(r, r);
  }
  function bnMod(a) {
    var r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
    return r;
  }
  function Classic(m) {
    this.m = m;
  }
  function cConvert(x) {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    else return x;
  }
  function cRevert(x) {
    return x;
  }
  function cReduce(x) {
    x.divRemTo(this.m, null, x);
  }
  function cMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
  }
  function cSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
  }
  Classic.prototype.convert = cConvert;
  Classic.prototype.revert = cRevert;
  Classic.prototype.reduce = cReduce;
  Classic.prototype.mulTo = cMulTo;
  Classic.prototype.sqrTo = cSqrTo;
  function bnpInvDigit() {
    if (this.t < 1) return 0;
    var x = this[0];
    if ((x & 1) == 0) return 0;
    var y = x & 3;
    y = (y * (2 - (x & 15) * y)) & 15;
    y = (y * (2 - (x & 255) * y)) & 255;
    y = (y * (2 - (((x & 65535) * y) & 65535))) & 65535;
    y = (y * (2 - ((x * y) % this.DV))) % this.DV;
    return y > 0 ? this.DV - y : -y;
  }
  function Montgomery(m) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 32767;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
  }
  function montConvert(x) {
    var r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
    return r;
  }
  function montRevert(x) {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }
  function montReduce(x) {
    while (x.t <= this.mt2) x[x.t++] = 0;
    for (var i = 0; i < this.m.t; ++i) {
      var j = x[i] & 32767;
      var u0 =
        (j * this.mpl +
          (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) &
        x.DM;
      j = i + this.m.t;
      x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
      while (x[j] >= x.DV) {
        x[j] -= x.DV;
        x[++j]++;
      }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
  }
  function montSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
  }
  function montMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
  }
  Montgomery.prototype.convert = montConvert;
  Montgomery.prototype.revert = montRevert;
  Montgomery.prototype.reduce = montReduce;
  Montgomery.prototype.mulTo = montMulTo;
  Montgomery.prototype.sqrTo = montSqrTo;
  function bnpIsEven() {
    return (this.t > 0 ? this[0] & 1 : this.s) == 0;
  }
  function bnpExp(e, z) {
    if (e > 4294967295 || e < 1) return BigInteger.ONE;
    var r = nbi(),
      r2 = nbi(),
      g = z.convert(this),
      i = nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
      z.sqrTo(r, r2);
      if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
      else {
        var t = r;
        r = r2;
        r2 = t;
      }
    }
    return z.revert(r);
  }
  function bnModPowInt(e, m) {
    var z;
    if (e < 256 || m.isEven()) z = new Classic(m);
    else z = new Montgomery(m);
    return this.exp(e, z);
  }
  BigInteger.prototype.copyTo = bnpCopyTo;
  BigInteger.prototype.fromInt = bnpFromInt;
  BigInteger.prototype.fromString = bnpFromString;
  BigInteger.prototype.clamp = bnpClamp;
  BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
  BigInteger.prototype.drShiftTo = bnpDRShiftTo;
  BigInteger.prototype.lShiftTo = bnpLShiftTo;
  BigInteger.prototype.rShiftTo = bnpRShiftTo;
  BigInteger.prototype.subTo = bnpSubTo;
  BigInteger.prototype.multiplyTo = bnpMultiplyTo;
  BigInteger.prototype.squareTo = bnpSquareTo;
  BigInteger.prototype.divRemTo = bnpDivRemTo;
  BigInteger.prototype.invDigit = bnpInvDigit;
  BigInteger.prototype.isEven = bnpIsEven;
  BigInteger.prototype.exp = bnpExp;
  BigInteger.prototype.toString = bnToString;
  BigInteger.prototype.negate = bnNegate;
  BigInteger.prototype.abs = bnAbs;
  BigInteger.prototype.compareTo = bnCompareTo;
  BigInteger.prototype.bitLength = bnBitLength;
  BigInteger.prototype.mod = bnMod;
  BigInteger.prototype.modPowInt = bnModPowInt;
  BigInteger.ZERO = nbv(0);
  BigInteger.ONE = nbv(1);
  function bnpFromRadix(s, b) {
    this.fromInt(0);
    if (b == null) b = 10;
    var cs = this.chunkSize(b);
    var d = Math.pow(b, cs),
      mi = false,
      j = 0,
      w = 0;
    for (var i = 0; i < s.length; ++i) {
      var x = intAt(s, i);
      if (x < 0) {
        if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
        continue;
      }
      w = b * w + x;
      if (++j >= cs) {
        this.dMultiply(d);
        this.dAddOffset(w, 0);
        j = 0;
        w = 0;
      }
    }
    if (j > 0) {
      this.dMultiply(Math.pow(b, j));
      this.dAddOffset(w, 0);
    }
    if (mi) BigInteger.ZERO.subTo(this, this);
  }
  function bnpChunkSize(r) {
    return Math.floor((Math.LN2 * this.DB) / Math.log(r));
  }
  function bnSigNum() {
    if (this.s < 0) return -1;
    else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
    else return 1;
  }
  function bnpDMultiply(n) {
    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
  }
  function bnpDAddOffset(n, w) {
    if (n == 0) return;
    while (this.t <= w) this[this.t++] = 0;
    this[w] += n;
    while (this[w] >= this.DV) {
      this[w] -= this.DV;
      if (++w >= this.t) this[this.t++] = 0;
      ++this[w];
    }
  }
  function bnpToRadix(b) {
    if (b == null) b = 10;
    if (this.signum() == 0 || b < 2 || b > 36) return "0";
    var cs = this.chunkSize(b);
    var a = Math.pow(b, cs);
    var d = nbv(a),
      y = nbi(),
      z = nbi(),
      r = "";
    this.divRemTo(d, y, z);
    while (y.signum() > 0) {
      r = (a + z.intValue()).toString(b).substr(1) + r;
      y.divRemTo(d, y, z);
    }
    return z.intValue().toString(b) + r;
  }
  function bnIntValue() {
    if (this.s < 0) {
      if (this.t == 1) return this[0] - this.DV;
      else if (this.t == 0) return -1;
    } else if (this.t == 1) return this[0];
    else if (this.t == 0) return 0;
    return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
  }
  function bnpAddTo(a, r) {
    var i = 0,
      c = 0,
      m = Math.min(a.t, this.t);
    while (i < m) {
      c += this[i] + a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c += a.s;
      while (i < this.t) {
        c += this[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c += a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c > 0) r[i++] = c;
    else if (c < -1) r[i++] = this.DV + c;
    r.t = i;
    r.clamp();
  }
  BigInteger.prototype.fromRadix = bnpFromRadix;
  BigInteger.prototype.chunkSize = bnpChunkSize;
  BigInteger.prototype.signum = bnSigNum;
  BigInteger.prototype.dMultiply = bnpDMultiply;
  BigInteger.prototype.dAddOffset = bnpDAddOffset;
  BigInteger.prototype.toRadix = bnpToRadix;
  BigInteger.prototype.intValue = bnIntValue;
  BigInteger.prototype.addTo = bnpAddTo;
  var Wrapper = {
    abs: function (l, h) {
      var x = new goog.math.Long(l, h);
      var ret;
      if (x.isNegative()) {
        ret = x.negate();
      } else {
        ret = x;
      }
      HEAP32[tempDoublePtr >> 2] = ret.low_;
      HEAP32[(tempDoublePtr + 4) >> 2] = ret.high_;
    },
    ensureTemps: function () {
      if (Wrapper.ensuredTemps) return;
      Wrapper.ensuredTemps = true;
      Wrapper.two32 = new BigInteger();
      Wrapper.two32.fromString("4294967296", 10);
      Wrapper.two64 = new BigInteger();
      Wrapper.two64.fromString("18446744073709551616", 10);
      Wrapper.temp1 = new BigInteger();
      Wrapper.temp2 = new BigInteger();
    },
    lh2bignum: function (l, h) {
      var a = new BigInteger();
      a.fromString(h.toString(), 10);
      var b = new BigInteger();
      a.multiplyTo(Wrapper.two32, b);
      var c = new BigInteger();
      c.fromString(l.toString(), 10);
      var d = new BigInteger();
      c.addTo(b, d);
      return d;
    },
    stringify: function (l, h, unsigned) {
      var ret = new goog.math.Long(l, h).toString();
      if (unsigned && ret[0] == "-") {
        Wrapper.ensureTemps();
        var bignum = new BigInteger();
        bignum.fromString(ret, 10);
        ret = new BigInteger();
        Wrapper.two64.addTo(bignum, ret);
        ret = ret.toString(10);
      }
      return ret;
    },
    fromString: function (str, base, min, max, unsigned) {
      Wrapper.ensureTemps();
      var bignum = new BigInteger();
      bignum.fromString(str, base);
      var bigmin = new BigInteger();
      bigmin.fromString(min, 10);
      var bigmax = new BigInteger();
      bigmax.fromString(max, 10);
      if (unsigned && bignum.compareTo(BigInteger.ZERO) < 0) {
        var temp = new BigInteger();
        bignum.addTo(Wrapper.two64, temp);
        bignum = temp;
      }
      var error = false;
      if (bignum.compareTo(bigmin) < 0) {
        bignum = bigmin;
        error = true;
      } else if (bignum.compareTo(bigmax) > 0) {
        bignum = bigmax;
        error = true;
      }
      var ret = goog.math.Long.fromString(bignum.toString());
      HEAP32[tempDoublePtr >> 2] = ret.low_;
      HEAP32[(tempDoublePtr + 4) >> 2] = ret.high_;
      if (error) throw "range error";
    },
  };
  return Wrapper;
})();
if (memoryInitializer) {
  if (typeof Module["locateFile"] === "function") {
    memoryInitializer = Module["locateFile"](memoryInitializer);
  } else if (Module["memoryInitializerPrefixURL"]) {
    memoryInitializer =
      Module["memoryInitializerPrefixURL"] + memoryInitializer;
  }
  if (ENVIRONMENT_IS_NODE || ENVIRONMENT_IS_SHELL) {
    var data = Module["readBinary"](memoryInitializer);
    HEAPU8.set(data, STATIC_BASE);
  } else {
    addRunDependency("memory initializer");
    Browser.asyncLoad(
      memoryInitializer,
      function (data) {
        HEAPU8.set(data, STATIC_BASE);
        removeRunDependency("memory initializer");
      },
      function (data) {
        throw "could not load memory initializer " + memoryInitializer;
      }
    );
  }
}
function ExitStatus(status) {
  this.name = "ExitStatus";
  this.message = "Program terminated with exit(" + status + ")";
  this.status = status;
}
ExitStatus.prototype = new Error();
ExitStatus.prototype.constructor = ExitStatus;
var initialStackTop;
var preloadStartTime = null;
var calledMain = false;
dependenciesFulfilled = function runCaller() {
  if (!Module["calledRun"] && shouldRunNow) run();
  if (!Module["calledRun"]) dependenciesFulfilled = runCaller;
};
Module["callMain"] = Module.callMain = function callMain(args) {
  assert(
    runDependencies == 0,
    "cannot call main when async dependencies remain! (listen on __ATMAIN__)"
  );
  assert(
    __ATPRERUN__.length == 0,
    "cannot call main when preRun functions remain to be called"
  );
  args = args || [];
  ensureInitRuntime();
  var argc = args.length + 1;
  function pad() {
    for (var i = 0; i < 4 - 1; i++) {
      argv.push(0);
    }
  }
  var argv = [
    allocate(intArrayFromString(Module["thisProgram"]), "i8", ALLOC_NORMAL),
  ];
  pad();
  for (var i = 0; i < argc - 1; i = i + 1) {
    argv.push(allocate(intArrayFromString(args[i]), "i8", ALLOC_NORMAL));
    pad();
  }
  argv.push(0);
  argv = allocate(argv, "i32", ALLOC_NORMAL);
  initialStackTop = STACKTOP;
  try {
    var ret = Module["_main"](argc, argv, 0);
    exit(ret);
  } catch (e) {
    if (e instanceof ExitStatus) {
      return;
    } else if (e == "SimulateInfiniteLoop") {
      Module["noExitRuntime"] = true;
      return;
    } else {
      if (e && typeof e === "object" && e.stack)
        Module.printErr("exception thrown: " + [e, e.stack]);
      throw e;
    }
  } finally {
    calledMain = true;
  }
};
function run(args) {
  args = args || Module["arguments"];
  if (preloadStartTime === null) preloadStartTime = Date.now();
  if (runDependencies > 0) {
    return;
  }
  preRun();
  if (runDependencies > 0) return;
  if (Module["calledRun"]) return;
  function doRun() {
    if (Module["calledRun"]) return;
    Module["calledRun"] = true;
    if (ABORT) return;
    ensureInitRuntime();
    preMain();
    if (ENVIRONMENT_IS_WEB && preloadStartTime !== null) {
      Module.printErr(
        "pre-main prep time: " + (Date.now() - preloadStartTime) + " ms"
      );
    }
    if (Module["onRuntimeInitialized"]) Module["onRuntimeInitialized"]();
    if (Module["_main"] && shouldRunNow) Module["callMain"](args);
    postRun();
  }
  if (Module["setStatus"]) {
    Module["setStatus"]("Running...");
    setTimeout(function () {
      setTimeout(function () {
        Module["setStatus"]("");
      }, 1);
      doRun();
    }, 1);
  } else {
    doRun();
  }
}
Module["run"] = Module.run = run;
function exit(status) {
  if (Module["noExitRuntime"]) {
    return;
  }
  ABORT = true;
  EXITSTATUS = status;
  STACKTOP = initialStackTop;
  exitRuntime();
  if (ENVIRONMENT_IS_NODE) {
    process["stdout"]["once"]("drain", function () {
      process["exit"](status);
    });
    console.log(" ");
    setTimeout(function () {
      process["exit"](status);
    }, 500);
  } else if (ENVIRONMENT_IS_SHELL && typeof quit === "function") {
    quit(status);
  }
  throw new ExitStatus(status);
}
Module["exit"] = Module.exit = exit;
function abort(text) {
  if (text) {
    Module.print(text);
    Module.printErr(text);
  }
  ABORT = true;
  EXITSTATUS = 1;
  var extra =
    "\nIf this abort() is unexpected, build with -s ASSERTIONS=1 which can give more information.";
  throw "abort() at " + stackTrace() + extra;
}
Module["abort"] = Module.abort = abort;
if (Module["preInit"]) {
  if (typeof Module["preInit"] == "function")
    Module["preInit"] = [Module["preInit"]];
  while (Module["preInit"].length > 0) {
    Module["preInit"].pop()();
  }
}
var shouldRunNow = true;
if (Module["noInitialRun"]) {
  shouldRunNow = false;
}
run();
