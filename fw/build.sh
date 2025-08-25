#!/usr/bin/env bash
set -e
arm-none-eabi-gcc -mcpu=cortex-a9 -marm -nostdlib -ffreestanding -Os \
  -Wl,-Ttext=0x10000 -Wl,--build-id=none \
  hello.c -o hello.elf

# 可选：也产出原始bin
arm-none-eabi-objcopy -O binary hello.elf hello.bin
echo "built: fw/hello.elf (entry=0x10000)"