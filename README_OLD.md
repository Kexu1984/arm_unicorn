
这是一款基于unicorn的虚拟原型项目。
项目骨架：目录结构、依赖、最小可跑代码（CPU+MMIO UART），以及如何编译一段裸机 “Hello, World” 固件喂给它运行。

---

# 目录结构（建议）

```
armv7_unicorn/
├─ requirements.txt
├─ run.py                  # 入口：装载固件、跑CPU、串口输出
├─ soc/
│  ├─ __init__.py
│  ├─ cpu.py               # Unicorn ARMv7 封装
│  ├─ bus.py               # 简易地址解码/分发
│  └─ uart.py              # MMIO UART 外设（把写入当作打印）
└─ fw/
   ├─ hello.c              # 裸机例子（写MMIO UART）
   └─ build.sh             # 用 arm-none-eabi-gcc 编译
```

`requirements.txt`

```
unicorn
capstone
pyelftools
```

---

# 1) 最小外设：MMIO UART（Python）

`soc/uart.py`

```python
class Uart:
    # 简化寄存器映射
    THR = 0x00  # Transmit Holding Register

    def __init__(self, base=0x4000_1000):
        self.base = base
        self.buf = []

    def in_range(self, addr):
        return self.base <= addr < (self.base + 0x1000)

    def write(self, addr, size, value):
        off = addr - self.base
        if off == self.THR:
            ch = value & 0xFF
            self.buf.append(ch)
            if ch == 0x0A or len(self.buf) > 256:  # 行缓冲
                s = bytes(self.buf).decode(errors="replace")
                print(f"[UART] {s}", end="")
                self.buf.clear()
            return True
        return False

    def read(self, addr, size):
        # 简化：没有RX，返回0
        return 0
```

---

# 2) 简易总线：把 MMIO 分给设备

`soc/bus.py`

```python
class Bus:
    def __init__(self, devices):
        self.devs = devices  # 列表：有 in_range()/read()/write()

    def mmio_write(self, addr, size, value):
        for d in self.devs:
            if d.in_range(addr):
                return d.write(addr, size, value)
        return False  # 让 CPU 自己处理（例如写到RAM时返回False）

    def mmio_read(self, addr, size):
        for d in self.devs:
            if d.in_range(addr):
                return d.read(addr, size)
        return None     # None 表示未处理
```

---

# 3) CPU 封装（Unicorn ARMv7）

`soc/cpu.py`

```python
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INTR
from unicorn.arm_const import *

class Armv7CPU:
    def __init__(self, ram_base=0x10000, ram_size=0x200000):
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.ram_base = ram_base
        self.ram_size = ram_size
        self.mu.mem_map(self.ram_base, self.ram_size)

    def load_blob(self, addr, blob: bytes):
        self.mu.mem_write(addr, blob)

    def set_pc_sp(self, pc, sp):
        self.mu.reg_write(UC_ARM_REG_PC, pc)
        self.mu.reg_write(UC_ARM_REG_SP, sp)

    def add_mmio_hooks(self, bus):
        def on_write(mu, access, addr, size, value, _):
            handled = bus.mmio_write(addr, size, value)
            return handled  # True=已处理，False=交还Unicorn

        def on_read(mu, access, addr, size, value, _):
            res = bus.mmio_read(addr, size)
            if res is None:
                return False  # 交还Unicorn（如RAM）
            # 告诉 Unicorn 此次读的返回值
            mu.mem_write(addr, (res & ((1 << (size*8)) - 1)).to_bytes(size, 'little'))
            return True

        self.mu.hook_add(UC_HOOK_MEM_WRITE, on_write)
        self.mu.hook_add(UC_HOOK_MEM_READ, on_read)

        def on_intr(mu, intno, _):
            # 碰到 BKPT 等异常时停机
            print(f"[CPU] interrupt/break @ PC=0x{mu.reg_read(UC_ARM_REG_PC):08x}, int={intno}")
            mu.emu_stop()
        self.mu.hook_add(UC_HOOK_INTR, on_intr)

    def run_until(self, start, end=None):
        self.mu.emu_start(start, end if end else 0)  # end=0 表示不限定结束地址
```

---

# 4) 入口脚本：装载固件，跑起来

`run.py`

```python
import sys
from soc.cpu import Armv7CPU
from soc.bus import Bus
from soc.uart import Uart

# 固件加载：支持 .bin 或 .elf（用 pyelftools 读入口点）
def load_firmware(path):
    if path.endswith(".bin"):
        with open(path, "rb") as f:
            blob = f.read()
        return {"entry": 0x10000, "sp": 0x120000, "image": (0x10000, blob)}
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
```

---

# 5) 裸机 “Hello, World” 固件（ARMv7-A）

`fw/hello.c`（**极简**：把字符串逐字节写到 UART\_THR，最后触发 BKPT 停机）

```c
// 假定 ARMv7-A，MMU未开，向 0x40001000 写即为串口发送
#define UART_BASE   0x40001000
#define UART_THR    (*(volatile unsigned int*)(UART_BASE + 0x00))

static void puts(const char* s) {
    while (*s) {
        UART_THR = (unsigned int)(unsigned char)(*s++);
    }
    UART_THR = '\n';
}

int main(void) {
    puts("Hello, ARMv7 + Unicorn!");
    // 触发 BKPT 方便 Unicorn 停机
    __asm__ __volatile__("bkpt #0");
    while (1) { }
    return 0;
}
```

`fw/build.sh`

```bash
#!/usr/bin/env bash
set -e
arm-none-eabi-gcc -mcpu=cortex-a9 -marm -nostdlib -ffreestanding -Os \
  -Wl,-Ttext=0x10000 -Wl,--build-id=none \
  hello.c -o hello.elf

# 可选：也产出原始bin
arm-none-eabi-objcopy -O binary hello.elf hello.bin
echo "built: fw/hello.elf (entry=0x10000)"
```

> 说明
>
> * 我们把链接地址放到 `0x10000`，与 `run.py` 里的 RAM 基址一致。
> * 真实工程中你会有启动码（向量表、C 运行时初始化等），这里为了演示直接把 `main` 放在 `0x10000` 运行。
> * `bkpt #0` 能让 Unicorn 触发 `UC_HOOK_INTR`，从而结束仿真。

---

## 运行

```bash
pip install -r requirements.txt
cd fw && bash build.sh && cd ..
python run.py fw/hello.elf
```

你应该看到：

```
[BOOT] entry=0x00010000, sp=0x00120000
[UART] Hello, ARMv7 + Unicorn!
[CPU] interrupt/break @ PC=0x000100XX, int=...
```

