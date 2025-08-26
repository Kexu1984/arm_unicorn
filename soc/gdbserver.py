"""
GDB Remote Serial Protocol (RSP) server for ARM Unicorn emulator
"""
import socket
import threading
import struct
from typing import Optional


class GDBServer:
    def __init__(self, cpu, port=1234):
        self.cpu = cpu
        self.port = port
        self.socket = None
        self.client_socket = None
        self.running = False
        
    def start(self):
        """Start the GDB server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('localhost', self.port))
        self.socket.listen(1)
        
        print(f"[GDB] Server listening on port {self.port}")
        print(f"[GDB] Connect with: arm-none-eabi-gdb -ex 'target remote localhost:{self.port}'")
        
        self.running = True
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                print(f"[GDB] Client connected from {addr}")
                self.client_socket = client_socket
                self.handle_client()
            except Exception as e:
                if self.running:
                    print(f"[GDB] Error accepting connection: {e}")
                break
    
    def stop(self):
        """Stop the GDB server"""
        self.running = False
        if self.client_socket:
            self.client_socket.close()
        if self.socket:
            self.socket.close()
    
    def handle_client(self):
        """Handle GDB client communication"""
        try:
            while self.running:
                packet = self.receive_packet()
                if packet is None:
                    break
                
                response = self.process_packet(packet)
                if response is not None:
                    self.send_packet(response)
                    
        except Exception as e:
            print(f"[GDB] Client error: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
    
    def receive_packet(self) -> Optional[str]:
        """Receive a GDB packet"""
        try:
            # Look for packet start '$'
            while True:
                char = self.client_socket.recv(1)
                if not char:
                    return None
                if char == b'$':
                    break
                elif char == b'\x03':  # Ctrl-C interrupt
                    self.cpu.stopped = True
                    self.cpu.stop_reason = "interrupt"
                    if hasattr(self.cpu.mu, 'emu_stop'):
                        self.cpu.mu.emu_stop()
                    continue
            
            # Read packet data until '#'
            packet_data = b''
            while True:
                char = self.client_socket.recv(1)
                if not char:
                    return None
                if char == b'#':
                    break
                packet_data += char
            
            # Read 2-digit checksum
            checksum_bytes = self.client_socket.recv(2)
            if len(checksum_bytes) != 2:
                return None
            
            expected_checksum = int(checksum_bytes.decode(), 16)
            actual_checksum = sum(packet_data) & 0xff
            
            if expected_checksum == actual_checksum:
                # Send ACK
                self.client_socket.send(b'+')
                return packet_data.decode('ascii', errors='ignore')
            else:
                # Send NACK
                self.client_socket.send(b'-')
                return None
                
        except Exception as e:
            print(f"[GDB] Error receiving packet: {e}")
            return None
    
    def send_packet(self, data: str):
        """Send a GDB packet"""
        try:
            packet_data = data.encode('ascii')
            checksum = sum(packet_data) & 0xff
            packet = b'$' + packet_data + b'#' + f'{checksum:02x}'.encode()
            self.client_socket.send(packet)
        except Exception as e:
            print(f"[GDB] Error sending packet: {e}")
    
    def process_packet(self, packet: str) -> Optional[str]:
        """Process a GDB command packet"""
        if not packet:
            return None
        
        cmd = packet[0]
        args = packet[1:] if len(packet) > 1 else ""
        
        print(f"[GDB] Command: {packet}")
        
        try:
            if cmd == '?':
                # Query halt reason
                return self.cmd_halt_reason()
            elif cmd == 'g':
                # Read general registers
                return self.cmd_read_registers()
            elif cmd == 'G':
                # Write general registers
                return self.cmd_write_registers(args)
            elif cmd == 'm':
                # Read memory
                return self.cmd_read_memory(args)
            elif cmd == 'M':
                # Write memory
                return self.cmd_write_memory(args)
            elif cmd == 'c':
                # Continue execution
                return self.cmd_continue(args)
            elif cmd == 's':
                # Single step
                return self.cmd_step(args)
            elif cmd == 'k':
                # Kill/detach
                return self.cmd_kill()
            elif packet.startswith('qSupported'):
                # Query supported features
                return self.cmd_query_supported()
            elif packet.startswith('Z'):
                # Insert breakpoint
                return self.cmd_insert_breakpoint(args)
            elif packet.startswith('z'):
                # Remove breakpoint
                return self.cmd_remove_breakpoint(args)
            elif packet.startswith('qC'):
                # Current thread
                return "QC1"
            elif packet.startswith('qfThreadInfo'):
                # Thread info
                return "m1"
            elif packet.startswith('qsThreadInfo'):
                # Thread info continued
                return "l"
            elif packet.startswith('Hg') or packet.startswith('Hc'):
                # Set thread
                return "OK"
            else:
                # Unsupported command
                print(f"[GDB] Unsupported command: {packet}")
                return ""
                
        except Exception as e:
            print(f"[GDB] Error processing command {packet}: {e}")
            return "E01"
    
    def cmd_halt_reason(self) -> str:
        """Return reason for halt"""
        if self.cpu.stop_reason == "breakpoint":
            return "S05"  # SIGTRAP
        elif self.cpu.stop_reason == "step":
            return "S05"  # SIGTRAP
        elif self.cpu.stop_reason == "interrupt":
            return "S02"  # SIGINT
        else:
            return "S05"  # Default to SIGTRAP
    
    def cmd_read_registers(self) -> str:
        """Read all registers"""
        regs = self.cpu.read_registers()
        hex_data = ""
        
        # First 16 registers (r0-r15) are 32-bit
        for i in range(16):
            reg_bytes = struct.pack('<I', regs[i])
            hex_data += reg_bytes.hex()
        
        # FPU registers F0-F7 are 12 bytes each (96 bytes total)
        for i in range(8):
            # Each FPU register is 12 bytes (96 bits)
            fpu_reg = b'\x00' * 12  # Zero for now
            hex_data += fpu_reg.hex()
        
        # FPS register (4 bytes)
        fps_bytes = struct.pack('<I', 0)
        hex_data += fps_bytes.hex()
        
        # CPSR register (4 bytes)
        cpsr_bytes = struct.pack('<I', regs[-1])  # Last register is CPSR
        hex_data += cpsr_bytes.hex()
        
        return hex_data
    
    def cmd_write_registers(self, args: str) -> str:
        """Write all registers"""
        try:
            # Parse hex data into register values
            regs = []
            for i in range(0, len(args), 8):
                if i + 8 <= len(args):
                    reg_hex = args[i:i+8]
                    # Convert from little endian
                    reg_bytes = bytes.fromhex(reg_hex)
                    reg_val = struct.unpack('<I', reg_bytes)[0]
                    regs.append(reg_val)
            
            self.cpu.write_registers(regs)
            return "OK"
        except:
            return "E01"
    
    def cmd_read_memory(self, args: str) -> str:
        """Read memory: m<addr>,<length>"""
        try:
            addr_str, length_str = args.split(',', 1)
            addr = int(addr_str, 16)
            length = int(length_str, 16)
            
            data = self.cpu.read_memory(addr, length)
            if data is not None:
                return data.hex()
            else:
                return "E01"
        except:
            return "E01"
    
    def cmd_write_memory(self, args: str) -> str:
        """Write memory: M<addr>,<length>:<data>"""
        try:
            addr_length, data_hex = args.split(':', 1)
            addr_str, length_str = addr_length.split(',', 1)
            addr = int(addr_str, 16)
            length = int(length_str, 16)
            
            data = bytes.fromhex(data_hex)
            if len(data) == length and self.cpu.write_memory(addr, data):
                return "OK"
            else:
                return "E01"
        except:
            return "E01"
    
    def cmd_continue(self, args: str) -> str:
        """Continue execution"""
        # Start execution in a separate thread
        def run_cpu():
            self.cpu.continue_execution()
        
        thread = threading.Thread(target=run_cpu, daemon=True)
        thread.start()
        # Don't send immediate response - will send stop packet when stopped
        return None
    
    def cmd_step(self, args: str) -> str:
        """Single step execution"""
        self.cpu.single_step_execution()
        return "S05"  # SIGTRAP after step
    
    def cmd_kill(self) -> str:
        """Kill/detach"""
        self.running = False
        return "OK"
    
    def cmd_query_supported(self) -> str:
        """Query supported features"""
        return "PacketSize=1000;swbreak+"
    
    def cmd_insert_breakpoint(self, args: str) -> str:
        """Insert breakpoint: Z<type>,<addr>,<length>"""
        try:
            parts = args.split(',')
            bp_type = int(parts[0])
            addr = int(parts[1], 16)
            
            if bp_type == 0:  # Software breakpoint
                if self.cpu.set_breakpoint(addr):
                    return "OK"
            return "E01"
        except:
            return "E01"
    
    def cmd_remove_breakpoint(self, args: str) -> str:
        """Remove breakpoint: z<type>,<addr>,<length>"""
        try:
            parts = args.split(',')
            bp_type = int(parts[0])
            addr = int(parts[1], 16)
            
            if bp_type == 0:  # Software breakpoint
                if self.cpu.remove_breakpoint(addr):
                    return "OK"
            return "E01"
        except:
            return "E01"