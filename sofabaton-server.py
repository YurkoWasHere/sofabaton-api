#!/usr/bin/env python3
"""
SofaBaton Server - Listen for Hub Connection
"""

import socket
import sys
import time
import threading
import argparse

class SofaBatonServer:
    def __init__(self, listen_port=8002, hub_ip=None, hub_id="03862a23"):
        self.listen_port = listen_port
        self.hub_ip = hub_ip
        self.hub_id = hub_id
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
        
        # Hub identifier (configurable, default from original capture)
        packet.extend(bytes.fromhex(self.hub_id))
        
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
    
    def send_command(self, device_id=0x02, button_code=0xB6):
        """Send command to hub with device ID and button code"""
        if not self.authenticated:
            print("❌ Not authenticated!")
            return False
            
        if not self.client_sock:
            print("❌ No connection to hub")
            return False
            
        try:
            # Command format: a55a 02 3f [device_id] [button_code] [checksum]
            packet = bytearray([0xA5, 0x5A, 0x02, 0x3F, device_id, button_code])
            
            # Calculate checksum
            checksum = self.get_check_code(packet)
            packet.append(checksum)
            
            print(f"📤 Sending command - Device: {device_id:02x}, Button: {button_code:02x}")
            print(f"📤 Packet: {packet.hex()}")
            self.client_sock.send(bytes(packet))
            
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

    def send_volume_command(self, command_type="up"):
        """Send volume command to hub (legacy method)"""
        if command_type == "up":
            return self.send_command(0x02, 0xB6)
        elif command_type == "down":
            return self.send_command(0x02, 0xB9)
        else:
            print(f"❌ Unknown command: {command_type}")
            return False
    
    def interactive_mode(self):
        """Interactive mode for sending commands"""
        if not self.authenticated:
            print("❌ Not authenticated - can't enter interactive mode")
            return
            
        print("\n🎮 Interactive Mode")
        print("Commands:")
        print("  <device> <button>  - Custom command (hex values)")
        print("  <button>           - Button to default device 02")
        print("  quit               - Exit")
        print("\nButton shortcuts available:")
        print("  volumeup, volumedown, mute, menu, back")
        print("  nav_up, nav_down, nav_right")
        print("\nExamples:")
        print("  02 b6              - Volume up (device 02, button b6)")
        print("  01 a0              - Device 01, button a0")
        print("  mute               - Mute (device 02)")
        print("  menu               - Menu (device 02)")
        print("  01 nav_up          - Navigation up (device 01)")
        print("-" * 60)
        
        while self.running and self.client_sock:
            try:
                cmd = input("Enter command: ").strip().lower()
                
                if cmd == "quit":
                    break
                elif " " in cmd:
                    # Parse device ID and button code
                    parts = cmd.split()
                    if len(parts) == 2:
                        try:
                            device_id = int(parts[0], 16)
                            # Handle button shortcuts in interactive mode
                            button_shortcuts = {
                                'volumeup': 0xb6, 'volumedown': 0xb9, 'volume_up': 0xb6, 'volume_down': 0xb9,
                                'vol_up': 0xb6, 'vol_down': 0xb9, 'nav_up': 0xb3, 'nav_down': 0xb2, 
                                'nav_right': 0xb1, 'mute': 0xb8, 'menu': 0xb5, 'back': 0xb4,
                            }
                            
                            if parts[1].lower() in button_shortcuts:
                                button_code = button_shortcuts[parts[1].lower()]
                            else:
                                button_code = int(parts[1], 16)
                                
                            if 0 <= device_id <= 255 and 0 <= button_code <= 255:
                                self.send_command(device_id, button_code)
                            else:
                                print("❌ Device ID and button code must be 0-255 (00-FF)")
                        except ValueError:
                            print("❌ Invalid format. Use: <device_hex> <button_hex_or_shortcut>")
                    else:
                        print("❌ Use format: <device_hex> <button_hex_or_shortcut> (e.g., '02 b6' or '01 mute')")
                else:
                    # Single button command (uses default device 02)
                    button_shortcuts = {
                        'volumeup': 0xb6, 'volumedown': 0xb9, 'volume_up': 0xb6, 'volume_down': 0xb9,
                        'vol_up': 0xb6, 'vol_down': 0xb9, 'up': 0xb6, 'down': 0xb9,
                        'nav_up': 0xb3, 'nav_down': 0xb2, 'nav_right': 0xb1, 
                        'mute': 0xb8, 'menu': 0xb5, 'back': 0xb4,
                    }
                    
                    if cmd in button_shortcuts:
                        self.send_command(0x02, button_shortcuts[cmd])
                    else:
                        try:
                            button_code = int(cmd, 16)
                            if 0 <= button_code <= 255:
                                self.send_command(0x02, button_code)
                            else:
                                print("❌ Button code must be 0-255 (00-FF)")
                        except ValueError:
                            print("❌ Unknown command. Use: <button_shortcut>, <hex>, <device> <button>, or quit")
                    
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

def create_parser():
    parser = argparse.ArgumentParser(
        description='SofaBaton Server - Control SofaBaton Hub via TCP/UDP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick commands using shortcuts (uses default device 02)
  %(prog)s 192.168.40.65 --button volumeup           # Volume up
  %(prog)s 192.168.40.65 --button mute               # Mute
  %(prog)s 192.168.40.65 --button menu               # Menu
  %(prog)s 192.168.40.65 --button back               # Back button
  %(prog)s 192.168.40.65 -b nav_up                   # Navigation up
  
  # Send hex commands (default device is '02')
  %(prog)s 192.168.40.65 --button b6                 # Volume up (hex)
  %(prog)s 192.168.40.65 --device 01 --button a0     # Button a0 to device 01
  %(prog)s 192.168.40.65 -d 03 -b c5                 # Button c5 to device 03
  
  # Interactive mode for testing
  %(prog)s 192.168.40.65 --interactive               # Interactive mode
  
  # Button shortcuts available:
  #   volumeup, volumedown, mute, menu, back, nav_up, nav_down, nav_right
        """
    )
    
    # Required arguments
    parser.add_argument('hub_ip', 
                       help='SofaBaton hub IP address')
    
    # Mode selection (optional for special modes)
    parser.add_argument('--interactive', action='store_true',
                       help='Enter interactive mode for testing multiple commands')
    
    # Command arguments for send mode
    parser.add_argument('--device', '-d',
                       default='02',
                       help='Target device ID (hex: 01, 02, 03, etc.) (default: 02)')
    parser.add_argument('--button', '-b', 
                       help='Button code (hex: a0, b6, b9, etc.) or shortcut (volumeup, mute, menu, back, nav_up, etc.)')
    
    # Optional arguments
    parser.add_argument('--port', '-p',
                       type=int, default=8002,
                       help='TCP port (default: 8002)')
    parser.add_argument('--hub-id', 
                       default='03862a23',
                       help='Hub identifier for UDP discovery (default: 03862a23)')
    
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if args.interactive:
        # Interactive mode
        mode = 'interactive'
        device_id = None
        button_code = None
    elif args.button is not None:
        # Send mode (default)
        # Parse device ID (has default)
        try:
            device_id = int(args.device, 16)
            if not (0 <= device_id <= 255):
                parser.error("device must be valid hex value (00-FF)")
        except ValueError:
            parser.error("device must be valid hex value")
            
        # Parse button code (allow shortcuts)
        button_shortcuts = {
            # Volume controls
            'volumeup': 0xb6,
            'volumedown': 0xb9,
            'volume_up': 0xb6,
            'volume_down': 0xb9,
            'vol_up': 0xb6,
            'vol_down': 0xb9,
            
            # Navigation (conflicts with volume, so using nav_ prefix)
            'nav_up': 0xb3,
            'nav_down': 0xb2,
            'nav_right': 0xb1,
            
            # Common buttons
            'mute': 0xb8,
            'menu': 0xb5,
            'back': 0xb4,
        }
        
        if args.button.lower() in button_shortcuts:
            button_code = button_shortcuts[args.button.lower()]
        else:
            try:
                button_code = int(args.button, 16)
                if not (0 <= button_code <= 255):
                    parser.error("button must be valid hex value (00-FF)")
            except ValueError:
                parser.error("button must be valid hex value or shortcut (volumeup, mute, menu, back, nav_up, etc.)")
        
        mode = 'send'
    else:
        parser.error("Must specify --button or --interactive")
    
    server = SofaBatonServer(listen_port=args.port, hub_ip=args.hub_ip, hub_id=args.hub_id)
    
    print(f"🔧 Configuration:")
    print(f"   Hub IP: {args.hub_ip}")
    print(f"   Port: {args.port}")
    print(f"   Hub ID: {args.hub_id}")
    if mode == 'send':
        print(f"   Command: Device {device_id:02x}, Button {button_code:02x}")
    else:
        print(f"   Mode: {mode}")
    print()
    
    try:
        # Start server first - must be listening before UDP discovery
        print("🔍 Step 1: Start TCP Server")
        if not server.start_server():
            return
        
        # Give server time to fully bind and be ready for connections
        print("⏳ Ensuring TCP server is ready...")
        time.sleep(1)
        
        # Send UDP discovery for all modes (always needed)
        print("\n📡 Step 2: UDP Discovery")
        if not server.send_udp_discovery():
            return
        
        # Wait for hub connection (should happen quickly after UDP discovery)
        print("\n👂 Step 3: Wait for Hub Connection")
        if not server.wait_for_hub():
            return
        
        # Authenticate first (always needed)
        print("\n🔐 Step 4: Authentication")
        if server.handle_authentication():
            if mode == "send":
                print(f"\n📤 Step 5: Send Command - Device: {device_id:02x}, Button: {button_code:02x}")
                server.send_command(device_id, button_code)
            elif mode == "interactive":
                server.interactive_mode()
            else:
                print("✅ Authentication successful - ready for commands")
        else:
            print("❌ Authentication failed")
            
    except KeyboardInterrupt:
        print("\n⏹ Interrupted by user")
    finally:
        server.stop()

if __name__ == "__main__":
    main()
