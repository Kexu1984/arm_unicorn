class Uart:
    # 简化寄存器映射
    THR = 0x00  # Transmit Holding Register

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
            if ch == 0x0A or len(self.buf) > 256:  # 行缓冲
                s = bytes(self.buf).decode(errors="replace")
                print(f"[UART] {s}", end="")
                self.buf.clear()
            return True
        return False

    def read(self, addr, size):
        # 简化：没有RX，返回0
        return 0