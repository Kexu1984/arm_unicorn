from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INTR, UC_HOOK_CODE
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
        
        # Debug state
        self.debug_mode = False
        self.breakpoints = {}  # addr -> original_instruction
        self.single_step = False
        self.stopped = False
        self.stop_reason = "unknown"

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
            if self.debug_mode:
                self.stopped = True
                self.stop_reason = "breakpoint"
            mu.emu_stop()
        self.mu.hook_add(UC_HOOK_INTR, on_intr)

    def run_until(self, start, end=None):
        self.mu.emu_start(start, end if end else 0)  # end=0 表示不限定结束地址
    
    # GDB debugging support methods
    def enable_debug_mode(self):
        """Enable debug mode with code hooks for stepping and breakpoints"""
        self.debug_mode = True
        
        def on_code_debug(mu, addr, size, _):
            # Check for breakpoints
            if addr in self.breakpoints:
                self.stopped = True
                self.stop_reason = "breakpoint"
                mu.emu_stop()
                return
            
            # Check for single step
            if self.single_step:
                self.single_step = False
                self.stopped = True
                self.stop_reason = "step"
                mu.emu_stop()
                return
        
        self.mu.hook_add(UC_HOOK_CODE, on_code_debug)
    
    def read_registers(self):
        """Read all general purpose registers for GDB"""
        regs = []
        # ARM general purpose registers r0-r12
        for i in range(13):
            reg_id = UC_ARM_REG_R0 + i
            regs.append(self.mu.reg_read(reg_id))
        
        # r13 (SP), r14 (LR), r15 (PC) - use the specific constants
        regs.append(self.mu.reg_read(UC_ARM_REG_SP))   # r13
        regs.append(self.mu.reg_read(UC_ARM_REG_LR))   # r14
        regs.append(self.mu.reg_read(UC_ARM_REG_PC))   # r15
        
        # CPSR (Current Program Status Register) 
        regs.append(self.mu.reg_read(UC_ARM_REG_CPSR))
        
        return regs
    
    def write_registers(self, regs):
        """Write general purpose registers from GDB"""
        # ARM general purpose registers r0-r12
        for i in range(min(13, len(regs))):
            reg_id = UC_ARM_REG_R0 + i
            self.mu.reg_write(reg_id, regs[i])
        
        # r13 (SP), r14 (LR), r15 (PC)
        if len(regs) > 13:
            self.mu.reg_write(UC_ARM_REG_SP, regs[13])
        if len(regs) > 14:
            self.mu.reg_write(UC_ARM_REG_LR, regs[14])
        if len(regs) > 15:
            self.mu.reg_write(UC_ARM_REG_PC, regs[15])
        
        # CPSR if provided
        if len(regs) > 16:
            self.mu.reg_write(UC_ARM_REG_CPSR, regs[16])
    
    def read_memory(self, addr, size):
        """Read memory for GDB"""
        try:
            return self.mu.mem_read(addr, size)
        except:
            return None
    
    def write_memory(self, addr, data):
        """Write memory for GDB"""
        try:
            self.mu.mem_write(addr, data)
            return True
        except:
            return False
    
    def set_breakpoint(self, addr):
        """Set software breakpoint by replacing instruction with BKPT"""
        if addr in self.breakpoints:
            return True  # Already set
        
        try:
            # Read original instruction (4 bytes for ARM)
            orig_inst = self.mu.mem_read(addr, 4)
            self.breakpoints[addr] = orig_inst
            
            # Replace with BKPT instruction (0xe1200070 in ARM mode)
            bkpt_inst = b'\x70\x00\x20\xe1'  # Little endian BKPT #0
            self.mu.mem_write(addr, bkpt_inst)
            return True
        except:
            return False
    
    def remove_breakpoint(self, addr):
        """Remove software breakpoint by restoring original instruction"""
        if addr not in self.breakpoints:
            return True  # Not set
        
        try:
            # Restore original instruction
            orig_inst = self.breakpoints[addr]
            self.mu.mem_write(addr, orig_inst)
            del self.breakpoints[addr]
            return True
        except:
            return False
    
    def continue_execution(self):
        """Continue execution from current PC"""
        print(f"[CPU] Continuing execution from PC=0x{self.mu.reg_read(UC_ARM_REG_PC):08x}")
        self.stopped = False
        self.stop_reason = "unknown"
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        try:
            self.mu.emu_start(pc, 0)
            # If we get here, emulation ended
            if not self.stopped:
                self.stopped = True
                self.stop_reason = "exited"
        except Exception as e:
            print(f"[CPU] Emulation error: {e}")
            self.stopped = True
            self.stop_reason = "error"
    
    def single_step_execution(self):
        """Execute one instruction"""
        print(f"[CPU] Single step from PC=0x{self.mu.reg_read(UC_ARM_REG_PC):08x}")
        self.single_step = True
        self.stopped = False
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        try:
            self.mu.emu_start(pc, 0)
            # If we get here, emulation ended without single step completing
            if not self.stopped:
                self.stopped = True
                self.stop_reason = "step"
        except Exception as e:
            print(f"[CPU] Single step error: {e}")
            self.stopped = True
            self.stop_reason = "step"