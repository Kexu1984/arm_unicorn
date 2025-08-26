#!/usr/bin/env python3
"""
ARM Unicorn emulator with GDB server support

Usage: python run_gdb.py [firmware.elf] [--port PORT]
"""
import sys
import argparse
from soc.cpu import Armv7CPU
from soc.bus import Bus
from soc.uart import Uart
from soc.gdbserver import GDBServer

# Reuse firmware loading from run.py
def load_firmware(path):
    if path.endswith(".bin"):
        with open(path, "rb") as f:
            blob = f.read()
        return {"entry": 0x10000, "sp": 0x120000, "image": [(0x10000, blob)]}
    elif path.endswith(".elf"):
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as f:
            elf = ELFFile(f)
            entry = elf.header["e_entry"]
            # 简化：把所有 PT_LOAD 段写入内存
            images = []
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    vaddr = seg["p_vaddr"]
                    data  = seg.data()
                    images.append((vaddr, data))
            # 栈指针：若你的启动代码自己设置，这里给个临时值
            sp = 0x120000
            return {"entry": entry, "sp": sp, "image": images}
    else:
        raise SystemExit("firmware must be .bin or .elf")

def main():
    parser = argparse.ArgumentParser(description="ARM Unicorn emulator with GDB server")
    parser.add_argument("firmware", nargs="?", default="fw/hello.elf", 
                       help="Firmware file (.bin or .elf)")
    parser.add_argument("--port", type=int, default=1234,
                       help="GDB server port (default: 1234)")
    
    args = parser.parse_args()
    
    print(f"[BOOT] Loading firmware: {args.firmware}")
    info = load_firmware(args.firmware)

    # Initialize CPU and peripherals
    cpu  = Armv7CPU()
    uart = Uart(base=0x40001000)
    bus  = Bus([uart])

    # Load firmware into memory
    for addr, blob in info["image"]:
        cpu.load_blob(addr, blob)

    cpu.set_pc_sp(info["entry"], info["sp"])
    cpu.add_mmio_hooks(bus)
    
    # Enable debug mode
    cpu.enable_debug_mode()
    
    # Set initial state as stopped at entry point
    cpu.stopped = True
    cpu.stop_reason = "start"

    print(f"[BOOT] entry=0x{info['entry']:08x}, sp=0x{info['sp']:08x}")
    print(f"[BOOT] CPU ready for debugging")
    
    # Start GDB server
    gdb_server = GDBServer(cpu, port=args.port)
    
    try:
        gdb_server.start()
    except KeyboardInterrupt:
        print("\n[GDB] Server interrupted")
    finally:
        gdb_server.stop()

if __name__ == "__main__":
    main()