class Uart:
    # 简化寄存器映射
    THR = 0x00  # Transmit Holding Register
    LSR = 0x14  # Line Status Register
    LSR_THRE = 1 << 5  # THR Empty

    def __init__(self, base=0x40001000):
        self.base = base
        self.buf = []

    def in_range(self, addr):
        return self.base <= addr < (self.base + 0x1000)

    def write(self, addr, size, value):
        off = addr - self.base
        if off == self.THR:
            ch = value & 0xFF
            self.buf.append(ch)
            # More aggressive output - print immediately for debugging
            print(chr(ch), end='')
            if ch == 0x0A:  # Also flush on newlines
                import sys
                sys.stdout.flush()
            return True
        return False

    def read(self, addr, size):
        off = addr - self.base
        if off == self.LSR:
            return self.LSR_THRE  # Always ready to transmit
        # 简化：没有RX，其他寄存器返回0
        return 0