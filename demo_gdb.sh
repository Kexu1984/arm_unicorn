#!/bin/bash
# Demo script for ARM Unicorn GDB Server
# Shows basic debugging capabilities

echo "=========================================="
echo "ARM Unicorn GDB Server Demo"
echo "=========================================="
echo

# Check if required tools are available
if ! command -v gdb-multiarch &> /dev/null; then
    echo "Error: gdb-multiarch not found. Install with:"
    echo "  sudo apt-get install gdb-multiarch"
    exit 1
fi

if [ ! -f "fw/hello.elf" ]; then
    echo "Building firmware..."
    cd fw && ./build.sh && cd ..
fi

echo "Starting GDB server in background..."
python run_gdb.py fw/hello.elf --port 1235 &
GDB_PID=$!
sleep 2

echo "Creating demo GDB session..."
cat > /tmp/demo_gdb_commands.txt << 'EOF'
set architecture arm
target remote localhost:1235

echo \n=== Initial State ===\n
info registers

echo \n=== Memory at PC ===\n
x/4i $pc

echo \n=== Single Step ===\n
stepi
info registers pc

echo \n=== Memory Content ===\n
x/10x 0x10000

echo \n=== Continue to End ===\n
continue

echo \n=== Final State ===\n
info registers

quit
EOF

echo "Running GDB commands..."
echo "========================================"
gdb-multiarch -batch -x /tmp/demo_gdb_commands.txt fw/hello.elf

echo
echo "========================================"
echo "Demo completed!"
echo
echo "To start an interactive session:"
echo "1. Run: python run_gdb.py fw/hello.elf"
echo "2. In another terminal: gdb-multiarch fw/hello.elf"
echo "3. In GDB: set architecture arm"
echo "4. In GDB: target remote localhost:1235"
echo

# Cleanup
kill $GDB_PID 2>/dev/null
wait $GDB_PID 2>/dev/null
rm -f /tmp/demo_gdb_commands.txt

echo "Demo script finished."