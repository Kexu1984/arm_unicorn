import sys
from soc.cpu import Armv7CPU
from soc.bus import Bus
from soc.uart import Uart

# 固件加载：支持 .bin 或 .elf（用 pyelftools 读入口点）
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
    fw = sys.argv[1] if len(sys.argv) > 1 else "fw/hello.elf"
    info = load_firmware(fw)

    cpu  = Armv7CPU()
    uart = Uart(base=0x40001000)
    bus  = Bus([uart])

    for addr, blob in info["image"]:
        cpu.load_blob(addr, blob)

    cpu.set_pc_sp(info["entry"], info["sp"])
    cpu.add_mmio_hooks(bus)

    print(f"[BOOT] entry=0x{info['entry']:08x}, sp=0x{info['sp']:08x}")
    cpu.run_until(info["entry"], end=None)

if __name__ == "__main__":
    main()