#!/usr/bin/env bash
set -e
ARM=arm-none-eabi
CFLAGS="-mcpu=cortex-m0 -mthumb -Os -ffreestanding -nostdlib -g -T cortex-m0.ld"

# Build hello_cm0.elf
$ARM-gcc $CFLAGS startup_cm0.c hello_cm0.c -o hello_cm0.elf
echo "built: fw/hello_cm0.elf"

# Build wfi_test_cm0.elf (exclude hello_cm0.c to avoid duplicate main)
$ARM-gcc $CFLAGS startup_cm0.c wfi_test_cm0.c -o wfi_test_cm0.elf
echo "built: fw/wfi_test_cm0.elf"