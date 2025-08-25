# run_cm0.py
from unicorn import *
from unicorn.arm_const import *
from soc.vclock import VirtualClock, EventLoop
from soc.bus import Bus
from soc.uart_timing import UartTiming

FLASH_BASE = 0x00000000
RAM_BASE   = 0x20000000
FLASH_SIZE = 0x00100000   # 1MB
RAM_SIZE   = 0x00020000   # 128KB

UART0_BASE = 0x40001000

# Thumb: WFI = 0xBF30 (小端)
WFI_THUMB = b"\x30\xBF"

def load_elf_into(mu, path):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        # 映射段
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                vaddr = seg['p_vaddr']
                data  = seg.data()
                if len(data) > 0:  # Only load non-empty segments
                    mu.mem_write(vaddr, data)
        entry = elf.header['e_entry']
    # Cortex-M 启动：向量表[0]=MSP, [1]=Reset
    sp = int.from_bytes(mu.mem_read(FLASH_BASE + 0, 4), "little")
    pc = int.from_bytes(mu.mem_read(FLASH_BASE + 4, 4), "little") | 1  # Thumb bit
    return entry, sp, pc

def main(fw="fw/hello_cm0.elf"):
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)  # Use only THUMB mode since MCLASS not available
    mu.mem_map(FLASH_BASE, FLASH_SIZE)
    mu.mem_map(RAM_BASE,   RAM_SIZE)
    
    # Map MMIO region for peripherals
    MMIO_BASE = 0x40000000
    MMIO_SIZE = 0x10000000  # 256MB MMIO space
    mu.mem_map(MMIO_BASE, MMIO_SIZE)

    entry, sp, pc = load_elf_into(mu, fw)
    mu.reg_write(UC_ARM_REG_SP, sp)
    mu.reg_write(UC_ARM_REG_PC, pc)

    vclk = VirtualClock(ips=80_000_000)
    ev   = EventLoop(vclk.now)
    
    # Use timing-based UART or simple UART based on command line argument
    import sys
    if len(sys.argv) > 2 and sys.argv[2] == "--simple":
        from soc.uart import Uart
        uart0 = Uart(UART0_BASE)  # Simple immediate output UART
    else:
        uart0 = UartTiming(UART0_BASE, ev, vclk.now, irq_cb=None, pclk=24_000_000)
    
    bus  = Bus([uart0])

    # Add unmapped memory hooks to catch detailed errors
    def on_mem_unmapped(mu_, access, addr, size, value, _):
        if access == UC_MEM_WRITE_UNMAPPED:
            print(f"[ERROR] Unmapped write: addr=0x{addr:08X}, size={size}, value=0x{value:X}")
        elif access == UC_MEM_READ_UNMAPPED:
            print(f"[ERROR] Unmapped read: addr=0x{addr:08X}, size={size}")
        return False
    
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_mem_unmapped)

    # MMIO 钩子
    def on_write(mu_, access, addr, size, value, _):
        handled = bus.mmio_write(addr, size, value)
        return handled

    def on_read(mu_, access, addr, size, value, _):
        res = bus.mmio_read(addr, size)
        if res is None:
            return False
        mu_.mem_write(addr, (res & ((1 << (size*8))-1)).to_bytes(size, "little"))
        return True

    mu.hook_add(UC_HOOK_MEM_WRITE, on_write)
    mu.hook_add(UC_HOOK_MEM_READ,  on_read)
    
    # Add interrupt hook to handle BKPT
    def on_intr(mu_, intno, _):
        pc = mu_.reg_read(UC_ARM_REG_PC)
        print(f"[CPU] Breakpoint/exception at PC=0x{pc:08X}, stopping emulation")
        mu_.emu_stop()
    
    mu.hook_add(UC_HOOK_INTR, on_intr)

    # 指令钩子：推进虚拟时间 + 处理事件 + 识别 WFI
    K = 2000  # 每K条指令批量推进一次，权衡性能
    icounter = {"n": 0}

    def on_code(mu_, addr, size, _):
        # 识别 WFI
        try:
            insn = bytes(mu_.mem_read(addr, 2))
            if insn == WFI_THUMB:
                # 停机，跳时到下一事件
                mu_.emu_stop()
                # 把时间推进到"下一个事件时刻"
                t_next = ev.next_deadline()
                if t_next == float('inf'):
                    return
                # 刷新到当前时刻
                vclk.flush()
                # 把虚拟时间直接跳到下一事件，并执行到期事件
                vclk.t = t_next
                ev.run_until(t_next)
                # 事件执行后恢复 CPU（从 WFI 的下一条继续）
                mu_.reg_write(UC_ARM_REG_PC, addr + 2)  # Thumb 2字节
                return
        except UcError:
            pass

        # 非 WFI：正常推进虚拟时间并执行到期事件
        icounter["n"] += 1
        vclk.on_insn(1)
        if (icounter["n"] % K) == 0:
            vclk.flush()
            ev.run_due()

    mu.hook_add(UC_HOOK_CODE, on_code)

    print(f"[BOOT] SP=0x{sp:08X}, PC=0x{pc:08X}")
    print(f"[BOOT] FLASH mapped: 0x{FLASH_BASE:08X} - 0x{FLASH_BASE + FLASH_SIZE - 1:08X}")
    print(f"[BOOT] RAM mapped: 0x{RAM_BASE:08X} - 0x{RAM_BASE + RAM_SIZE - 1:08X}")
    
    try:
        mu.emu_start(pc, 0)  # 跑到 BKPT/异常/我们手动 emu_stop
    except UcError as e:
        pc_at_error = mu.reg_read(UC_ARM_REG_PC)
        print(f"Emu error at PC=0x{pc_at_error:08X}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()