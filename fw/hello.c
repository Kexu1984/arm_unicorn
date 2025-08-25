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