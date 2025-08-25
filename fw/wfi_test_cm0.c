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
  while ((UART_LSR & LSR_THRE) == 0) { 
    // Wait for transmit holding register empty
    // In a real system, this might use WFI to save power
  }
  UART_THR = (unsigned char)c;
}

static void uart_puts(const char* s) {
  while (*s) uart_putc(*s++);
  uart_putc('\n');
}

static void wait_for_events(void) {
  // Demonstrate WFI - wait for interrupt/event
  // This should cause the virtual time to jump to the next event
  __asm volatile("wfi");
}

int main(void) {
  uart_init_115200();
  uart_puts("Cortex-M0 WFI Test Starting...");
  
  // Send a character, then wait for its transmission to complete
  uart_putc('A');
  uart_puts(" - Char sent, now WFI...");
  
  // This WFI should jump virtual time forward
  wait_for_events();
  
  uart_puts("WFI completed!");
  uart_puts("Test finished.");
  return 0;
}