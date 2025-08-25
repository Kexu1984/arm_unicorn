from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INTR
from unicorn.arm_const import *

class Armv7CPU:
    def __init__(self, ram_base=0x10000, ram_size=0x200000):
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.ram_base = ram_base
        self.ram_size = ram_size
        self.mu.mem_map(self.ram_base, self.ram_size)
        
        # Map MMIO region for UART
        self.mmio_base = 0x40000000
        self.mmio_size = 0x10000
        self.mu.mem_map(self.mmio_base, self.mmio_size)

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