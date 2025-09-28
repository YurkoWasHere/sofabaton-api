#!/usr/bin/env python3
"""
SofaBaton Server - Listen for Hub Connection

Flow from packet capture:
1. Server listens on a port (likely 8002)
2. Server sends UDP Packets to hub
3. Hub initiates TCP connection to phone
3. Normal handshake: a55a 0001 00 -> response
4. Volume commands work: a55a 023f 02b6 f8 / a55a 023f 02b9 fb
"""

import socket
import sys
import time
import threading

class SofaBatonServer:
    def __init__(self, listen_port=8002, hub_ip=None):
        self.listen_port = listen_port
        self.hub_ip = hub_ip
        self.server_sock = None
        self.client_sock = None
        self.authenticated = False
        self.running = False
    
    def get_local_ip(self):
        """Get local IP address that can reach the hub"""
        try:
            # Create a socket to the hub to determine local IP
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_sock.connect((self.hub_ip, 8102))
            local_ip = temp_sock.getsockname()[0]
            temp_sock.close()
            return local_ip
        except Exception:
            # Fallback to localhost if can't determine
            return "127.0.0.1"
    

    def get_check_code(self, data: bytes) -> int:
        # Sum all bytes as unsigned
        total = sum(b & 0xFF for b in data)
        # Return only the low byte of the sum
        return total & 0xFF

    def calculate_checksum(self, data):
        """Calculate checksum like APK getCheckCode method"""
        # Sum all bytes as unsigned values
        total = sum(b for b in data)
        
        # Convert to 4-byte int and return last byte
        total_bytes = total.to_bytes(4, byteorder='big')
        return total_bytes[-1]
    
    def create_discovery_packet(self):
        """Create UDP discovery packet with local IP and proper checksum"""
        # Get local IP that hub should connect back to
        local_ip = self.get_local_ip()
        print(f"🔍 Local IP for hub callback: {local_ip}")
        
        # Parse original packet structure:
        # a55a0cc3e0df03862a23c0a828551f42a9
        # a55a - header
        # 0c - length (12 bytes)  
        # c3 - command
        # e0df - identifier
        # 03862a23 - Device identifier (4 bytes)
        # c0a82855 - IP address 192.168.40.85
        # 1f42 - Port 8002 (little-endian)
        # a9 - Checksum
        
        # Build packet with our local IP
        packet = bytearray()
        packet.extend([0xA5, 0x5A])  # Header
        packet.extend([0x0C])        # Length
        packet.extend([0xC3])        # Command
        packet.extend([0xE0, 0xDF])  # Identifier
        
        # Device identifier (keep original - might be phone-specific)
        packet.extend(bytes.fromhex("03862a23"))
        
        # Convert local IP to bytes
        ip_parts = [int(part) for part in local_ip.split('.')]
        packet.extend(ip_parts)
        
        # Port number (8002 = 0x1f42, little-endian)
        port = self.listen_port
        port_bytes = port.to_bytes(2, byteorder='little')
        port_bytes = port.to_bytes(2, byteorder='big')
        packet.extend(port_bytes)
        
        # Calculate and append checksum
        checksum = self.calculate_checksum(packet)
        checksum = self.get_check_code(packet)
        packet.append(checksum)
        
        return bytes(packet)
    
    def send_udp_discovery(self):
        """Send UDP discovery packet to hub to trigger connection"""
        if not self.hub_ip:
            print("❌ No hub IP provided for UDP discovery")
            return False
            
        try:
            print(f"📡 Sending UDP discovery to {self.hub_ip}:8102")
            
            # Create discovery packet with local IP
            discovery_packet = self.create_discovery_packet()
            
            # Create UDP socket
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(5)
            
            # Send discovery packet
            udp_sock.sendto(discovery_packet, (self.hub_ip, 8102))
            print(f"📤 Sent UDP discovery: {discovery_packet.hex()}")
                
            udp_sock.close()
            print("✅ UDP discovery sent - hub should connect back now")
            return True
            
        except Exception as e:
            print(f"❌ UDP discovery failed: {e}")
            return False
        
    def start_server(self):
        """Start listening for hub connections"""
        try:
            print(f"🚀 Starting SofaBaton server on port {self.listen_port}")
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(('', self.listen_port))
            self.server_sock.listen(1)
            self.running = True
            
            print(f"👂 Listening on 0.0.0.0:{self.listen_port} for hub connection...")
            print("💡 Make sure your hub is configured to connect to this IP")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return False
    
    def wait_for_hub(self, timeout=60):
        """Wait for hub to connect"""
        try:
            print(f"⏳ Waiting up to {timeout} seconds for hub connection...")
            self.server_sock.settimeout(timeout)
            
            self.client_sock, addr = self.server_sock.accept()
            print(f"✅ Hub connected from {addr}")
            
            # Set timeout for client socket
            self.client_sock.settimeout(10)
            return True
            
        except socket.timeout:
            print("⏰ Timeout waiting for hub connection")
            return False
        except Exception as e:
            print(f"❌ Error waiting for connection: {e}")
            return False
    
    def handle_authentication(self):
        """Handle authentication when hub connects"""
        if not self.client_sock:
            print("❌ No client connection")
            return False
            
        try:
            print("🔐 Sending authentication request to hub...")
            
            # Send auth request to hub (we initiate)
            auth_request = bytes([0xA5, 0x5A, 0x00, 0x01, 0x00])
            print(f"📤 Sending auth request: {auth_request.hex()}")
            self.client_sock.send(auth_request)
            
            # Wait for auth response from hub
            print("⏳ Waiting for auth response...")
            data = self.client_sock.recv(1024)
            if data:
                print(f"📥 Received from hub: {data.hex()}")
                
                # Check if it's an auth response (should be a55a with device info)
                if len(data) >= 5 and data[0:2] == bytes([0xA5, 0x5A]):
                    print("🔑 Received valid auth response from hub")
                    print(f"📋 Response length: {len(data)} bytes")
                    print(f"📋 Response data: {data.hex()}")
                    
                    self.authenticated = True
                    print("✅ Authentication completed")
                    return True
                else:
                    print(f"❌ Invalid auth response format: {data.hex()}")
                    return False
            else:
                print("❌ No data received from hub")
                return False
                
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False
    
    def send_volume_command(self, command_type="up"):
        """Send volume command to hub"""
        if not self.authenticated:
            print("❌ Not authenticated!")
            return False
            
        if not self.client_sock:
            print("❌ No connection to hub")
            return False
            
        try:
            if command_type == "up":
                # Volume up: a55a 023f 02b6 f8
                packet = bytes([0xA5, 0x5A, 0x02, 0x3F, 0x02, 0xB6, 0xF8])
                desc = "Volume Up"
            elif command_type == "down":
                # Volume down: a55a 023f 02b9 fb  
                packet = bytes([0xA5, 0x5A, 0x02, 0x3F, 0x02, 0xB9, 0xFB])
                desc = "Volume Down"
            else:
                print(f"❌ Unknown command: {command_type}")
                return False
            
            print(f"📤 Sending {desc}: {packet.hex()}")
            self.client_sock.send(packet)
            
            # Try to get response
            try:
                self.client_sock.settimeout(2)
                response = self.client_sock.recv(1024)
                if response:
                    print(f"📥 Hub response: {response.hex()}")
                else:
                    print("📥 No response from hub")
            except socket.timeout:
                print("📥 No response from hub (timeout)")
            
            return True
            
        except Exception as e:
            print(f"❌ Command failed: {e}")
            return False
    
    def interactive_mode(self):
        """Interactive mode for sending commands"""
        if not self.authenticated:
            print("❌ Not authenticated - can't enter interactive mode")
            return
            
        print("\n🎮 Interactive Mode")
        print("Commands: up, down, quit")
        print("-" * 30)
        
        while self.running and self.client_sock:
            try:
                cmd = input("Enter command (up/down/quit): ").strip().lower()
                
                if cmd == "quit":
                    break
                elif cmd == "up":
                    self.send_volume_command("up")
                elif cmd == "down":
                    self.send_volume_command("down")
                else:
                    print("Unknown command. Use: up, down, quit")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                break
    
    def listen_for_packets(self):
        """Continuously listen for packets from hub"""
        if not self.client_sock:
            return
            
        try:
            print("👂 Listening for packets from hub... (Ctrl+C to stop)")
            while self.running:
                try:
                    self.client_sock.settimeout(1)
                    data = self.client_sock.recv(1024)
                    if data:
                        print(f"📥 Hub sent: {data.hex()}")
                    else:
                        print("Hub disconnected")
                        break
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving data: {e}")
                    break
        except KeyboardInterrupt:
            print("\n⏹ Stopping packet listener")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.client_sock:
            self.client_sock.close()
            self.client_sock = None
        if self.server_sock:
            self.server_sock.close()
            self.server_sock = None
        print("🔌 Server stopped")

def main():
    if len(sys.argv) < 3:
        print("SofaBaton Server - Listen for Hub Connection")
        print("=" * 50)
        print("Usage:")
        print(f"  {sys.argv[0]} <hub_ip> <mode> [port]")
        print("")
        print("Modes:")
        print("  listen      - Just listen and show packets")
        print("  auth        - UDP discovery + listen + authenticate")
        print("  volume_up   - UDP discovery + listen + auth + send volume up")
        print("  volume_down - UDP discovery + listen + auth + send volume down")
        print("  interactive - UDP discovery + listen + auth + interactive mode")
        print("")
        print("Examples:")
        print(f"  {sys.argv[0]} 192.168.40.65 listen")
        print(f"  {sys.argv[0]} 192.168.40.65 auth 8002")
        print(f"  {sys.argv[0]} 192.168.40.65 interactive")
        return
    
    hub_ip = sys.argv[1]
    mode = sys.argv[2].lower()
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8002
    
    server = SofaBatonServer(listen_port=port, hub_ip=hub_ip)
    
    try:
        # Start server first - must be listening before UDP discovery
        print("🔍 Step 1: Start TCP Server")
        if not server.start_server():
            return
        
        # Give server time to fully bind and be ready for connections
        print("⏳ Ensuring TCP server is ready...")
        time.sleep(1)
        
        # Send UDP discovery if mode requires it (hub will connect back immediately)
        if mode in ["auth", "volume_up", "volume_down", "interactive"]:
            print("\n📡 Step 2: UDP Discovery")
            if not server.send_udp_discovery():
                return
        
        # Wait for hub connection (should happen quickly after UDP discovery)
        print("\n👂 Step 3: Wait for Hub Connection")
        if not server.wait_for_hub():
            return
        
        if mode == "listen":
            # Just listen for packets
            server.listen_for_packets()
            
        elif mode in ["auth", "volume_up", "volume_down", "interactive"]:
            # Authenticate first
            print("\n🔐 Step 4: Authentication")
            if server.handle_authentication():
                if mode == "volume_up":
                    print("\n📤 Step 5: Send Volume Up")
                    server.send_volume_command("up")
                elif mode == "volume_down":
                    print("\n📤 Step 5: Send Volume Down (x2)")
                    server.send_volume_command("down")
                    time.sleep(0.5)  # Small delay between commands
                    server.send_volume_command("down")
                elif mode == "interactive":
                    server.interactive_mode()
                else:
                    print("✅ Authentication successful - ready for commands")
            else:
                print("❌ Authentication failed")
        
        else:
            print(f"❌ Unknown mode: {mode}")
            
    except KeyboardInterrupt:
        print("\n⏹ Interrupted by user")
    finally:
        server.stop()

if __name__ == "__main__":
    main()
