#include <stdint.h>
#define VECTORS __attribute__((section(".isr_vector")))
extern int main(void);

void Reset_Handler(void) {
  main();
  // 打印完就停
  __asm volatile("bkpt 0");
  while (1) {}
}

// Use a fixed stack pointer for simplicity
#define INITIAL_SP 0x2001FF00  // Within 128KB RAM range

VECTORS void (* const g_pfnVectors[])(void) = {
  (void (*)(void))(INITIAL_SP),  // 初始 MSP
  Reset_Handler,                 // Reset
  0,0,0,0,0,0,0,0,0,            // 预留中断
};