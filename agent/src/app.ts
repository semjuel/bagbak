import ObjC from "frida-objc-bridge";
import type { MachOTasks } from "./shared.js";
import { getApi } from "./shared.js";

const HIGH_WATER_MARK = 1024 * 1024;
const O_RDWR = 0x0002;

const EXTENSION_SYMBOLS = [
  "libxpc.dylib`xpc_main",
  "Foundation`NSExtensionMain",
  "ExtensionFoundation`EXExtensionMain",
];

const APP_SYMBOLS = ["UIKitCore`UIApplicationMain", "AppKit`NSApplicationMain"];

const EXIT_SYMBOLS = [
  "libsystem_c.dylib`exit",
  "libsystem_kernel.dylib`_exit",
  "libsystem_kernel.dylib`__exit",
];

// Keep a module-level reference so Frida never garbage-collects the callback
// while threads are parked inside it.
const parkThreadCallback = new NativeCallback(
  () => {
    const { sleep } = getApi();
    while (true) {
      sleep(3600);
    }
    return 0;
  },
  "int",
  [],
);

function replaceWithPark(symbols: string[]) {
  for (const symbol of symbols) {
    const [dylib, func] = symbol.split("`");
    try {
      const mod = Process.findModuleByName(dylib);
      if (!mod) continue;
      const p = mod.findExportByName(func);
      if (!p) continue;
      console.log("replace function", symbol, p);
      Interceptor.replace(p, parkThreadCallback);
    } catch (e: unknown) {
      console.log("skip", symbol, (e as Error).message);
    }
  }

  for (const symbol of EXIT_SYMBOLS) {
    const [dylib, func] = symbol.split("`");
    try {
      const mod = Process.findModuleByName(dylib);
      if (!mod) continue;
      const p = mod.findExportByName(func);
      if (!p) continue;
      Interceptor.replace(p, parkThreadCallback);
    } catch {
      // ignore
    }
  }

  if (ObjC.available) {
    ObjC.schedule(ObjC.mainQueue, () => {
      console.log("mainQueue scheduled");
    });
  }
}

rpc.exports = {
  hookAppMain() {
    replaceWithPark(APP_SYMBOLS);
  },
  hookExtensionMain() {
    replaceWithPark(EXTENSION_SYMBOLS);
  },

  dump(
    remoteRoot: string,
    tempRoot: string,
    binaries: MachOTasks,
    isExtension: boolean = false,
  ) {
    const { open, close, pwrite } = getApi();

    for (const [relative, info] of Object.entries(binaries)) {
      console.log("decrypt", relative);

      const { offset, size } = info.encrypt;
      const absoluteOriginal = remoteRoot + "/" + relative;
      const absoluteTemp = tempRoot + "/" + relative;

      const mod = Module.load(absoluteOriginal);
      const fatOffset = Process.findRangeByAddress(mod.base)!.file!.offset;

      console.log("module =>", mod.name, mod.base, mod.size);
      console.log("encrypted =>", offset, size, "fatOffset =>", fatOffset);

      const fd = open(Memory.allocUtf8String(absoluteTemp), O_RDWR) as number;
      if (fd < 0) {
        console.error("Failed to open", absoluteTemp);
        continue;
      }

      let p = mod.base.add(offset);
      let fileOffset = offset + fatOffset;
      let remaining = size;

      while (remaining > 0) {
        const chunk = Math.min(HIGH_WATER_MARK, remaining);
        pwrite(fd, p, chunk, fileOffset);
        p = p.add(chunk);
        fileOffset += chunk;
        remaining -= chunk;
      }

      // patch LC_ENCRYPTION_INFO_64: zero out cryptoff, cryptsize, cryptid
      const zeros = Memory.alloc(12);
      pwrite(fd, zeros, 12, info.offset + 8 + fatOffset);

      close(fd);

      send({ event: "patch", name: relative });
      recv("ack", () => {}).wait();
    }

    return true;
  },
};
