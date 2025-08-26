# ARM Unicorn GDB Server

This implementation provides a GDB remote debugging server for the ARM Unicorn emulator, allowing you to debug ARM firmware using standard GDB tools.

## Features

- **Remote debugging**: Connect with any GDB client that supports ARM
- **Register inspection**: Read/write all ARM general purpose registers
- **Memory access**: Read/write memory from the emulated system
- **Single stepping**: Execute one instruction at a time
- **Continue execution**: Run the program until breakpoint or completion
- **Basic breakpoint support**: Software breakpoints using instruction patching

## Usage

### Starting the GDB Server

```bash
# Start GDB server with default firmware and port
python run_gdb.py

# Specify firmware file
python run_gdb.py fw/hello.elf

# Specify custom port
python run_gdb.py fw/hello.elf --port 1234
```

### Connecting with GDB

```bash
# Using gdb-multiarch (recommended for cross-debugging)
gdb-multiarch fw/hello.elf
(gdb) set architecture arm
(gdb) target remote localhost:1234

# Using arm-none-eabi-gdb if available
arm-none-eabi-gdb fw/hello.elf
(gdb) target remote localhost:1234
```

### GDB Commands

Once connected, you can use standard GDB commands:

```gdb
# View registers
info registers

# View memory (hex format)
x/10x $pc

# Disassemble instructions
x/10i $pc

# Single step
stepi

# Continue execution
continue

# Set breakpoints
break *0x10000
break main

# View current location
info registers pc
```

## Example Debugging Session

```bash
# Terminal 1: Start GDB server
$ python run_gdb.py fw/hello.elf
[BOOT] Loading firmware: fw/hello.elf
[BOOT] entry=0x00010000, sp=0x00120000
[BOOT] CPU ready for debugging
[GDB] Server listening on port 1234
[GDB] Connect with: arm-none-eabi-gdb -ex 'target remote localhost:1234'

# Terminal 2: Connect with GDB
$ gdb-multiarch fw/hello.elf
(gdb) set architecture arm
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
0x00010000 in main ()

(gdb) info registers
r0             0x0      0
r1             0x0      0
...
pc             0x10000  0x10000 <main>

(gdb) x/4i $pc
=> 0x10000 <main>:      ldr     r1, [pc, #36]
   0x10004 <main+4>:    ldr     r3, [pc, #36]
   0x10008 <main+8>:    ldrb    r2, [r1], #1
   0x1000c <main+12>:   cmp     r2, #0

(gdb) stepi
0x00010004 in main ()

(gdb) continue
Program received signal SIGTRAP, Trace/breakpoint trap.
0x0001001c in main ()
```

## Architecture

### Files Added/Modified

- **`run_gdb.py`**: Main entry point for GDB debugging mode
- **`soc/gdbserver.py`**: GDB Remote Serial Protocol implementation  
- **`soc/cpu.py`**: Added debugging support methods to Armv7CPU class

### GDB Remote Serial Protocol (RSP)

The implementation supports these key GDB commands:

- `g` / `G`: Read/write general registers
- `m` / `M`: Read/write memory
- `c`: Continue execution  
- `s`: Single step
- `Z` / `z`: Insert/remove breakpoints
- `?`: Query halt reason
- `qSupported`: Feature negotiation

### Technical Details

- **Port**: Default port 1234 (configurable)
- **Architecture**: ARM 32-bit (ARMv7)
- **Breakpoints**: Software breakpoints using BKPT instruction patching
- **Memory mapping**: Preserves original memory layout from run.py
- **Registers**: Full ARM register set (r0-r15, CPSR)

## Limitations

- Only software breakpoints are supported (no hardware breakpoints)
- No support for watchpoints
- Basic thread support (single thread model)
- Limited floating-point register support

## Testing

A test script is provided to verify functionality:

```bash
# Run automated test
/tmp/test_gdb_simple.sh
```

This will start the GDB server, connect with gdb-multiarch, and run basic debugging commands to verify the implementation works correctly.