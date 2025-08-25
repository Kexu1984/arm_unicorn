# ARM Unicorn 虚拟原型项目

这是一款基于unicorn的虚拟原型项目。现在包含两个原型：

1. **ARMv7 原型** - 基础的 Unicorn ARMv7 虚拟机
2. **Cortex-M0 事件驱动原型** - 支持指令驱动虚拟时钟、事件队列和带时序的 UART

---

## 目录结构

```
arm_unicorn/
├─ requirements.txt
├─ run.py                  # ARMv7 入口：装载固件、跑CPU、串口输出
├─ run_cm0.py              # Cortex-M0 入口：事件驱动原型
├─ soc/
│  ├─ __init__.py
│  ├─ cpu.py               # Unicorn ARMv7 封装
│  ├─ bus.py               # 简易地址解码/分发
│  ├─ uart.py              # MMIO UART 外设（把写入当作打印）
│  ├─ vclock.py            # VirtualClock + EventLoop（时钟和事件系统）
│  └─ uart_timing.py       # 带时序的 UART（支持波特率、位时间模拟）
└─ fw/
   ├─ hello.c              # ARMv7 裸机例子（写MMIO UART）
   ├─ hello_cm0.c          # Cortex-M0 裸机例子
   ├─ startup_cm0.c        # Cortex-M0 向量表 + Reset_Handler
   ├─ cortex-m0.ld         # Cortex-M0 链接脚本
   ├─ build.sh             # 用 arm-none-eabi-gcc 编译 ARMv7
   └─ build_cm0.sh         # 用 arm-none-eabi-gcc 编译 Cortex-M0
```

## 依赖

```
unicorn
capstone
pyelftools
```

---

## Cortex-M0 事件驱动原型

### 特性

* **CPU**：Unicorn 以 **ARM Thumb** 运行 Cortex-M0 代码
* **时钟**：用"每条指令≈若干 CPU 周期"的近似推进 **VirtualClock**（虚拟时间）
* **事件**：UART 位时序、定时器到期等，都挂在 **EventLoop**（小顶堆）上，**到期才触发**（跳时）
* **WFI**：遇到 `WFI` 指令，**直接把虚拟时间跳到下个事件**，事件若产生可用中断/状态就"唤醒"继续跑
* **UART**：支持按 `baud` 逐位"播放"TX 帧（start/data/parity/stop），寄存器可用简化的 16550 风格

### 虚拟时钟和事件系统

`soc/vclock.py` 实现了基于指令计数的虚拟时钟：

```python
class VirtualClock:
    def __init__(self, ips=80_000_000):  # 80M 指令/秒
        self.t = 0.0       # 虚拟秒
        self.ips = float(ips)
        self._insn_acc = 0

    def on_insn(self, n=1):
        self._insn_acc += n

    def flush(self):
        if self._insn_acc:
            self.t += self._insn_acc / self.ips
            self._insn_acc = 0

class EventLoop:
    def __init__(self, now_fn):
        self.heap = []
        self.now = now_fn
        self._id = 0

    def schedule_at(self, t, cb):
        self._id += 1
        item = [t, self._id, cb, True]
        heapq.heappush(self.heap, item)
        return item

    def next_deadline(self):
        return self.heap[0][0] if self.heap else float('inf')

    def run_due(self):
        now = self.now()
        while self.heap and self.heap[0][0] <= now:
            t, _, cb, alive = heapq.heappop(self.heap)
            if alive:
                cb(t)
```

### 带时序的 UART

`soc/uart_timing.py` 实现了真实的串口时序：

```python
class UartTiming:
    # 16550风格的最小寄存器子集（只做 TX）
    THR = 0x00  # 写入=发送
    IER = 0x04  # 中断使能（用作占位）
    LSR = 0x14  # 线路状态
    LSR_THRE = 1 << 5  # THR Empty (TX FIFO 空)

    # 波特率配置简化：DLL/DLM
    DLL = 0x00; DLM = 0x04  # 复用：当 LCR.DLAB=1 时访问
    LCR = 0x0C; LCR_DLAB = 1 << 7

    def __init__(self, base, evloop, now_fn, irq_cb=None, pclk=24_000_000):
        # 支持波特率配置和位时间计算
        # 按位时间事件推进传输
```

特性：
- 按位时间事件推进传输
- 支持波特率配置（通过 DLL/DLM 寄存器）
- 帧格式：start bit + data bits + stop bits
- 轮询式状态检查（LSR.THRE）

### WFI 指令处理

在 `run_cm0.py` 中，代码钩子检测 WFI 指令：

```python
# Thumb: WFI = 0xBF30 (小端)
WFI_THUMB = b"\x30\xBF"

def on_code(mu_, addr, size, _):
    try:
        insn = bytes(mu_.mem_read(addr, 2))
        if insn == WFI_THUMB:
            # 停机，跳时到下一事件
            mu_.emu_stop()
            t_next = ev.next_deadline()
            if t_next != float('inf'):
                vclk.flush()
                vclk.t = t_next
                ev.run_until(t_next)
                # 从 WFI 的下一条继续
                mu_.reg_write(UC_ARM_REG_PC, addr + 2)
    except UcError:
        pass
```

### 编译和运行

```bash
# 安装依赖
pip install -r requirements.txt

# 编译 Cortex-M0 固件
cd fw
./build_cm0.sh

# 运行 Cortex-M0 原型
cd ..
python3 run_cm0.py fw/hello_cm0.elf

# 使用简单 UART（即时输出，用于调试）
python3 run_cm0.py fw/hello_cm0.elf --simple
```

### 输出示例

```
[BOOT] SP=0x2001FF00, PC=0x0000002D
[BOOT] FLASH mapped: 0x00000000 - 0x000FFFFF
[BOOT] RAM mapped: 0x20000000 - 0x2001FFFF
Hello from Cortex-M0 + Unicorn!
[CPU] Breakpoint/exception at PC=0x00000032, stopping emulation
```

---

## ARMv7 原型（原有功能）

### 运行 ARMv7 示例

```bash
# 编译 ARMv7 固件
cd fw
./build.sh

# 运行 ARMv7 原型
cd ..
python3 run.py fw/hello.elf
```

### 输出示例

```
[BOOT] entry=0x00010000, sp=0x00120000
[UART] Hello, ARMv7 + Unicorn!
[CPU] interrupt/break @ PC=0x0001001c, int=7
```

---

## 架构说明

### 总线和设备

`soc/bus.py` 实现简易地址解码：

```python
class Bus:
    def __init__(self, devices):
        self.devs = devices

    def mmio_write(self, addr, size, value):
        for d in self.devs:
            if d.in_range(addr):
                return d.write(addr, size, value)
        return False

    def mmio_read(self, addr, size):
        for d in self.devs:
            if d.in_range(addr):
                return d.read(addr, size)
        return None
```

### 内存映射

**Cortex-M0 内存映射：**
- FLASH: 0x00000000 - 0x000FFFFF (1MB)
- RAM: 0x20000000 - 0x2001FFFF (128KB)
- MMIO: 0x40000000 - 0x4FFFFFFF (256MB)
- UART0: 0x40001000

**ARMv7 内存映射：**
- RAM: 0x10000 - 0x20FFFF (2MB)
- MMIO: 0x40000000 - 0x4000FFFF (64KB)
- UART: 0x40001000

---

## 开发说明

### 添加新外设

1. 在 `soc/` 目录下创建外设类
2. 实现 `in_range()`, `read()`, `write()` 方法
3. 在 `run_cm0.py` 或 `run.py` 中添加到总线

### 时序仿真

事件驱动原型支持：
- 指令级时间模拟
- 外设时序事件
- WFI 低功耗模拟
- 中断和事件唤醒

### 调试技巧

- 使用 `--simple` 参数启用即时 UART 输出
- 查看内存映射和加载调试信息
- 使用 `arm-none-eabi-objdump` 分析生成的固件
- 检查向量表和启动代码