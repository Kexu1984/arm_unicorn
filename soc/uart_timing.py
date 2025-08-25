# soc/uart_timing.py
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
        self.base = base
        self.ev  = evloop
        self.now = now_fn
        self.irq = irq_cb or (lambda : None)
        self.pclk = pclk

        self.tx_fifo = []
        self.sending = False
        self.cur_bits = []
        self.next_ev = None

        self.lsr = self.LSR_THRE
        self.ier = 0
        self.lcr = 0  # 含 DLAB
        self.dll = 13  # 默认 115200 for 24MHz / (16*13)≈115384
        self.dlm = 0

        self.data_bits = 8
        self.stop_bits = 1
        self.parity = None
        self._update_baud()

    def _update_baud(self):
        div = (self.dlm << 8) | self.dll
        div = max(1, div)
        self.baud = self.pclk / (16 * div)
        self.bit_t = 1.0 / self.baud

    def in_range(self, addr): return self.base <= addr < self.base + 0x1000

    def _frame_bits(self, byte):
        bits = [0]  # start
        for i in range(self.data_bits):
            bits.append((byte >> i) & 1)
        if self.parity is not None:
            p = sum(bits[1:]) & 1
            bits.append(p if self.parity == "odd" else (p ^ 1))
        bits += [1] * self.stop_bits
        return bits

    def _kick(self):
        if self.sending:
            return
        if not self.tx_fifo:
            self.lsr |= self.LSR_THRE
            # 可选：THRE中断
            if self.ier & (1 << 1):
                self.irq()
            return
        byte = self.tx_fifo.pop(0)
        self.cur_bits = self._frame_bits(byte)
        self.sending = True
        t0 = self.now() + self.bit_t
        self.next_ev = self.ev.schedule_at(t0, self._on_bit_edge)

    def _on_bit_edge(self, now):
        bit = self.cur_bits.pop(0)
        # Optional: trace bit transmission timing
        # print(f"[UART TX] t={now:.6f}s bit={bit}")
        
        if self.cur_bits:
            self.next_ev = self.ev.schedule_at(now + self.bit_t, self._on_bit_edge)
        else:
            # Frame transmission complete
            self.sending = False
            # Output the completed character
            if hasattr(self, '_last_byte'):
                import sys
                print(chr(self._last_byte), end='')
                sys.stdout.flush()  # Force immediate output
            # 连续发送
            self._kick()

    def write(self, addr, size, value):
        off = addr - self.base
        if off == self.LCR:
            self.lcr = value & 0xFF
            # 低两位数据位，bit2 停止位，bit3-5 奇偶设置（此处省略解析，可后续补）
            # 这里只解析 DLAB
            return True
        if (self.lcr & self.LCR_DLAB) != 0:
            if off == self.DLL:
                self.dll = value & 0xFF; self._update_baud(); return True
            if off == self.DLM:
                self.dlm = value & 0xFF; self._update_baud(); return True

        if off == self.THR:
            ch = value & 0xFF
            self.tx_fifo.append(ch)
            self._last_byte = ch  # Store for output later
            self.lsr &= ~self.LSR_THRE
            self._kick()
            return True

        if off == self.IER:
            self.ier = value & 0x0F
            return True

        return False

    def read(self, addr, size):
        off = addr - self.base
        if off == self.LSR: return self.lsr
        # 其它寄存器读返回0即可
        return 0