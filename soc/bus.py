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