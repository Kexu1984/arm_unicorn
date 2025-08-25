MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 1M
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
}

SECTIONS
{
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))
        . = ALIGN(4);
    } >FLASH

    .text :
    {
        . = ALIGN(4);
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } >FLASH

    .data : 
    {
        . = ALIGN(4);
        *(.data*)
        . = ALIGN(4);
    } >RAM AT> FLASH

    .bss :
    {
        . = ALIGN(4);
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
    } >RAM

    _estack = ORIGIN(RAM) + LENGTH(RAM);
}