# soc/vclock.py
import heapq

class VirtualClock:
    def __init__(self, ips=80_000_000):  # 假设 M0 80M instr/sec 先近似
        self.t = 0.0       # 虚拟秒
        self.ips = float(ips)
        self._insn_acc = 0

    def on_insn(self, n=1):
        self._insn_acc += n

    def flush(self):
        if self._insn_acc:
            self.t += self._insn_acc / self.ips
            self._insn_acc = 0

    def now(self):
        return self.t


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

    def cancel(self, item):
        item[3] = False

    def next_deadline(self):
        return self.heap[0][0] if self.heap else float('inf')

    def run_due(self):
        now = self.now()
        while self.heap and self.heap[0][0] <= now:
            t, _, cb, alive = heapq.heappop(self.heap)
            if alive:
                cb(t)

    def run_until(self, t_until):
        # 把时间推进到某一时刻（用于 WFI 跳时）
        while self.heap and self.heap[0][0] <= t_until:
            self.run_due()
        # 外层别忘了把 vclock.t 设置为 t_until（见主循环）