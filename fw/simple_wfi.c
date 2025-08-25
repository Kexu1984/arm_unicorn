#include <stdint.h>
#define UART0_BASE  0x40001000u
#define UART_THR    (*(volatile uint32_t *)(UART0_BASE + 0x00))

static void uart_putc(char c) {
  UART_THR = (unsigned char)c;
}

static void uart_puts(const char* s) {
  while (*s) uart_putc(*s++);
  uart_putc('\n');
}

int main(void) {
  uart_puts("Start");
  __asm volatile("wfi");  // WFI instruction
  uart_puts("After WFI");
  return 0;
}