#!/usr/bin/env bash
set -e
ARM=arm-none-eabi
CFLAGS="-mcpu=cortex-m0 -mthumb -Os -ffreestanding -nostdlib -g -T cortex-m0.ld"
$ARM-gcc $CFLAGS startup_cm0.c hello_cm0.c -o hello_cm0.elf
echo "built: fw/hello_cm0.elf"