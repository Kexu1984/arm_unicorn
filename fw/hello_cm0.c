#include <stdint.h>
#define UART0_BASE  0x40001000u
#define UART_THR    (*(volatile uint32_t *)(UART0_BASE + 0x00))
#define UART_IER    (*(volatile uint32_t *)(UART0_BASE + 0x04))
#define UART_LCR    (*(volatile uint32_t *)(UART0_BASE + 0x0C))
#define UART_LSR    (*(volatile uint32_t *)(UART0_BASE + 0x14))
#define LCR_DLAB    (1u<<7)
#define LSR_THRE    (1u<<5)
#define UART_DLL    (*(volatile uint32_t *)(UART0_BASE + 0x00)) // DLAB=1
#define UART_DLM    (*(volatile uint32_t *)(UART0_BASE + 0x04)) // DLAB=1

static void uart_init_115200(void) {
  // 以 PCLK=24MHz 为例：div = 24_000_000/(16*115200) ≈ 13
  UART_LCR = LCR_DLAB;
  UART_DLL = 13;
  UART_DLM = 0;
  UART_LCR = 0; // 8N1，DLAB=0
  UART_IER = 0; // 先关中断，轮询发送
}

static void uart_putc(char c) {
  while ((UART_LSR & LSR_THRE) == 0) { /* 等待THR空 */ }
  UART_THR = (unsigned char)c;
}

static void uart_puts(const char* s) {
  while (*s) uart_putc(*s++);
  uart_putc('\n');
}

int main(void) {
  uart_init_115200();
  uart_puts("Hello from Cortex-M0 + Unicorn!");
  return 0;
}