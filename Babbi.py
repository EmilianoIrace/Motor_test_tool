I see the issue. The script might be having trouble processing your Bluetooth packets. Let's investigate and fix the problem. There are a few common reasons why you might be seeing zero packets analyzed:

1. The PyShark display filter might not be matching your packets
2. The .pcapng file might contain Bluetooth packets in a format that needs special handling
3. You might need additional dependencies for specific Bluetooth protocol support

Let me revise the script to address these issues:

```python
#!/usr/bin/env python3
import pyshark
import argparse
import pandas as pd
from collections import defaultdict, Counter
import sys
import os
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BluetoothSecurityAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.devices = {}
        self.connections = defaultdict(list)
        self.security_events = []
        self.vulnerabilities = []
        self.risk_score = 0
        self.packets_analyzed = 0
        
    def analyze(self):
        """Main analysis function"""
        try:
            logger.info(f"Opening capture file: {self.pcap_file}")
            
            # Try different display filters to ensure we capture all Bluetooth traffic
            # Start with no filter to see all packets
            cap = pyshark.FileCapture(self.pcap_file)
            
            # Process each packet
            for packet in cap:
                try:
                    # Check for any Bluetooth-related layers - more comprehensive approach
                    bt_layers = [layer.layer_name for layer in packet.layers 
                                if layer.layer_name.startswith(('bthci', 'btatt', 'btl2cap', 'btsmp', 'btsdp', 'btrfcomm'))]
                    
                    if bt_layers:
                        self.packets_analyzed += 1
                        if self.packets_analyzed % 100 == 0:
                            logger.info(f"Processed {self.packets_analyzed} Bluetooth packets...")
                        
                        self._process_packet(packet)
                    elif hasattr(packet, 'bluetooth'):
                        # Alternative check for bluetooth layer
                        self.packets_analyzed += 1
                        if self.packets_analyzed % 100 == 0:
                            logger.info(f"Processed {self.packets_analyzed} Bluetooth packets...")
                        
                        self._process_packet(packet)
                    
                    # Look for Bluetooth Low Energy packets
                    if hasattr(packet, 'btle') or (hasattr(packet, 'layers') and any('btle' in str(layer) for layer in packet.layers)):
                        self.packets_analyzed += 1
                        self._process_ble_packet(packet)
                        
                except (AttributeError, Exception) as e:
                    #logger.debug(f"Error processing packet: {str(e)}")
                    continue
            
            # If no Bluetooth packets found, try with explicit BLE filter
            if self.packets_analyzed == 0:
                logger.info("No Bluetooth packets found with general filter. Trying BLE specific filter...")
                cap = pyshark.FileCapture(self.pcap_file, display_filter="btle")
                
                for packet in cap:
                    try:
                        self.packets_analyzed += 1
                        if self.packets_analyzed % 100 == 0:
                            logger.info(f"Processed {self.packets_analyzed} BLE packets...")
                        
                        self._process_ble_packet(packet)
                    except Exception:
                        continue
            
            # Generate reports after analysis
            if self.packets_analyzed > 0:
                self._calculate_risk_score()
                logger.info(f"Analysis complete - processed {self.packets_analyzed} packets")
            else:
                # Try one last approach - look for any packets and extract MAC addresses
                logger.info("No Bluetooth packets detected with filters. Looking for MAC addresses in raw packets...")
                self._extract_mac_addresses_from_raw()
                
        except FileNotFoundError:
            logger.error(f"File not found: {self.pcap_file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error analyzing capture: {str(e)}")
            sys.exit(1)
    
    def _extract_mac_addresses_from_raw(self):
        """Extract MAC addresses from raw packets as last resort"""
        try:
            # Use more generic approach to find any MAC addresses
            cap = pyshark.FileCapture(self.pcap_file)
            mac_addresses = set()
            
            for packet in cap:
                # Look through all fields for potential MAC addresses
                packet_info = str(packet)
                
                # Simple regex pattern for MAC addresses would be ideal here
                # This is a simplified approach - looking for fields with "addr" in them
                for layer in packet.layers:
                    for field in dir(layer):
                        if 'addr' in field.lower() and not field.startswith('_'):
                            try:
                                value = getattr(layer, field)
                                if ':' in value and len(value) >= 12:  # Simple MAC format check
                                    mac_addresses.add(value)
                                    self._register_device(value)
                                    self.packets_analyzed += 1
                            except (AttributeError, TypeError):
                                pass
            
            if mac_addresses:
                logger.info(f"Found {len(mac_addresses)} potential MAC addresses in the capture")
                
        except Exception as e:
            logger.error(f"Error extracting raw MAC addresses: {str(e)}")
    
    def _process_packet(self, packet):
        """Process individual packets and extract information"""
        # Extract basic information like time
        timestamp = getattr(packet, 'sniff_timestamp', None)
        
        # Extract Bluetooth addresses from various layers
        for layer_name in dir(packet):
            if layer_name.startswith(('bthci', 'btatt', 'btsmp')):
                layer = getattr(packet, layer_name)
                self._extract_bt_info(layer, layer_name, timestamp)
    
    def _process_ble_packet(self, packet):
        """Process BLE specific packets"""
        if hasattr(packet, 'btle'):
            # Extract advertising address if available
            if hasattr(packet.btle, 'advertising_address'):
                addr = packet.btle.advertising_address
                self._register_device(addr)
                
                # Check privacy - random addresses are a privacy feature
                if hasattr(packet.btle, 'advertising_address_type'):
                    addr_type = packet.btle.advertising_address_type
                    self.devices[addr]['address_type'] = addr_type
                    
                    if addr_type == '1':  # Random address
                        self.devices[addr]['uses_privacy'] = True
                    else:
                        self.devices[addr]['uses_privacy'] = False
                        self._register_vulnerability("Device using public address - privacy concern", 
                                                  addr, severity=2)
            
            # Check for encryption
            if hasattr(packet.btle, 'data_header_llid'):
                # LLID of 3 often indicates encrypted data
                llid = packet.btle.data_header_llid
                if llid == '3':
                    for addr in self.devices:
                        if 'connection_handle' in self.devices[addr]:
                            self.devices[addr]['potential_encryption'] = True
    
    def _extract_bt_info(self, layer, layer_name, timestamp):
        """Extract Bluetooth information from a specific layer"""
        # Check for device addresses
        for field in dir(layer):
            # Look for BD_ADDR fields
            if 'bd_addr' in field.lower() and not field.startswith('_'):
                try:
                    addr = getattr(layer, field)
                    self._register_device(addr)
                    
                    # Look for connection handles to map addresses to connections
                    if hasattr(layer, 'connection_handle'):
                        self.devices[addr]['connection_handle'] = layer.connection_handle
                except (AttributeError, TypeError):
                    pass
        
        # Check for security-related information
        if layer_name == 'btsmp':
            self._extract_smp_info(layer)
        elif layer_name == 'bthci_evt' and hasattr(layer, 'code'):
            self._extract_hci_evt_info(layer)
        elif layer_name == 'bthci_cmd' and hasattr(layer, 'opcode'):
            self._extract_hci_cmd_info(layer)
    
    def _extract_smp_info(self, layer):
        """Extract Security Manager Protocol information"""
        # Check pairing method
        if hasattr(layer, 'io_capability'):
            io_cap = layer.io_capability
            
            # Get associated device if possible
            addr = None
            if hasattr(layer, 'bd_addr'):
                addr = layer.bd_addr
            
            if addr:
                self.devices[addr]['pairing_method'] = io_cap
                self.security_events.append({
                    'type': 'pairing_io_capability',
                    'device': addr,
                    'capability': io_cap
                })
                
                # Check for Just Works pairing (vulnerable to MITM)
                if io_cap == '0x03' or io_cap == '3':  # NoInputNoOutput
                    self._register_vulnerability("Using 'Just Works' pairing - vulnerable to MITM attacks", 
                                               addr, severity=5)
        
        # Check for encryption info
        if hasattr(layer, 'ltk'):
            # Long Term Key present
            if hasattr(layer, 'bd_addr'):
                addr = layer.bd_addr
                self.devices[addr]['has_ltk'] = True
    
    def _extract_hci_evt_info(self, layer):
        """Extract info from HCI Event packets"""
        if hasattr(layer, 'bd_addr'):
            addr = layer.bd_addr
            
            # Check encryption status
            if hasattr(layer, 'status'):
                status = layer.status
                if hasattr(layer, 'code') and layer.code == '8' and status == '0':
                    # Encryption Change event with status OK
                    if hasattr(layer, 'encryption_enabled') and layer.encryption_enabled == '1':
                        self.devices[addr]['encryption_enabled'] = True
                    else:
                        self.devices[addr]['encryption_enabled'] = False
            
            # Check encryption key size
            if hasattr(layer, 'enc_key_size'):
                key_size = int(layer.enc_key_size)
                self.devices[addr]['encryption_key_size'] = key_size
                
                if key_size < 16:
                    self._register_vulnerability(f"Weak encryption key size ({key_size} bytes)", 
                                               addr, severity=4)
    
    def _extract_hci_cmd_info(self, layer):
        """Extract info from HCI Command packets"""
        if hasattr(layer, 'bd_addr'):
            addr = layer.bd_addr
            
            # Check for pairing requests
            if hasattr(layer, 'opcode') and layer.opcode in ['0x0419', '0x041D']:  # Authentication requests
                self.security_events.append({
                    'type': 'authentication_request',
                    'device': addr
                })
            
            # Check for security flags
            if hasattr(layer, 'authentication_requirements'):
                auth_req = layer.authentication_requirements
                self.devices[addr]['authentication_requirements'] = auth_req
                
                if auth_req == '0x00':  # No MITM protection
                    self._register_vulnerability("No MITM protection requested", addr, severity=3)
    
    def _register_device(self, addr):
        """Register a device if not already tracked"""
        if not addr or not isinstance(addr, str):
            return
            
        # Normalize MAC address format
        addr = addr.lower()
        
        if addr not in self.devices:
            self.devices[addr] = {
                'packet_count': 0,
                'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'services': set(),
                'characteristics': set(),
                'encryption_enabled': False,
            }
        self.devices[addr]['packet_count'] += 1
        self.devices[addr]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def _register_vulnerability(self, description, device=None, severity=1):
        """Register a vulnerability with severity 1-5 (5 being most severe)"""
        # Avoid duplicate vulnerabilities
        for v in self.vulnerabilities:
            if v['description'] == description and v['device'] == device:
                return
                
        self.vulnerabilities.append({
            'description': description,
            'device': device,
            'severity': severity
        })
    
    def _calculate_risk_score(self):
        """Calculate overall security risk score (0-100, higher is more risky)"""
        if not self.vulnerabilities:
            self.risk_score = 0
            return
            
        # Base score on vulnerability severity
        severity_sum = sum(v['severity'] for v in self.vulnerabilities)
        severity_count = len(self.vulnerabilities)
        
        # Factor in number of devices and connections
        device_factor = min(len(self.devices), 10) / 10
        
        # Calculate final score (0-100)
        self.risk_score = min(100, (severity_sum / (severity_count * 5)) * 100 * (1 + device_factor))
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n===== BLUETOOTH SECURITY ANALYSIS REPORT =====")
        print(f"File analyzed: {self.pcap_file}")
        print(f"Total packets analyzed: {self.packets_analyzed}")
        print(f"Devices detected: {len(self.devices)}")
        
        if self.packets_analyzed == 0:
            print("\nWARNING: No Bluetooth packets were successfully processed.")
            print("This could be due to:")
            print("1. The capture file doesn't contain Bluetooth traffic")
            print("2. The capture uses a format or encapsulation not supported by this tool")
            print("3. You may need a different tool to analyze this specific capture")
            print("\nDEBUG TIPS:")
            print("- Try opening the file in Wireshark and verify it contains Bluetooth packets")
            print("- Check which protocols are present in the capture (use Wireshark's Statistics > Protocol Hierarchy)")
            print("- If you see BTLE packets in Wireshark but not here, you may need HCI-specific tools")
            return
        
        # Device information
        print("\n--- DEVICES DETECTED ---")
        for addr, info in self.devices.items():
            print(f"\nMAC Address: {addr}")
            print(f"  Packet count: {info['packet_count']}")
            if 'first_seen' in info:
                print(f"  First seen: {info['first_seen']}")
            if 'last_seen' in info:
                print(f"  Last seen: {info['last_seen']}")
            
            # Print any security-related information
            if 'authentication_requirements' in info:
                print(f"  Authentication Requirements: {info['authentication_requirements']}")
            if 'io_capability' in info:
                print(f"  IO Capability: {info['io_capability']}")
            if 'encryption_key_size' in info:
                print(f"  Encryption Key Size: {info['encryption_key_size']} bytes")
            if 'encryption_enabled' in info:
                print(f"  Encryption Enabled: {info['encryption_enabled']}")
            if 'address_type' in info:
                addr_type = "Random (Privacy-enabled)" if info['address_type'] == '1' else "Public"
                print(f"  Address Type: {addr_type}")
        
        # Vulnerabilities
        if self.vulnerabilities:
            print("\n--- SECURITY VULNERABILITIES ---")
            for vuln in sorted(self.vulnerabilities, key=lambda x: x['severity'], reverse=True):
                severity_text = '*' * vuln['severity'] + ' ' * (5 - vuln['severity'])
                device_text = f" (Device: {vuln['device']})" if vuln['device'] else ""
                print(f"[{severity_text}] {vuln['description']}{device_text}")
        
        # Overall rating
        print("\n--- SECURITY ASSESSMENT ---")
        print(f"Risk Score: {self.risk_score:.1f}/100")
        
        if self.risk_score < 20:
            rating = "EXCELLENT"
        elif self.risk_score < 40:
            rating = "GOOD"
        elif self.risk_score < 60:
            rating = "MODERATE"
        elif self.risk_score < 80:
            rating = "POOR"
        else:
            rating = "CRITICAL"
            
        print(f"Security Rating: {rating}")
        
        # Security recommendations
        print("\n--- RECOMMENDATIONS ---")
        if self.vulnerabilities:
            recommendations = {
                "Just Works pairing": "Use a pairing method with authentication to prevent MITM attacks",
                "Weak encryption": "Ensure encryption key size of at least 16 bytes",
                "Unencrypted communication": "Enable encryption for all sensitive communications",
                "No MITM protection": "Enable MITM protection in pairing process",
                "public address": "Use private/random addresses instead of public addresses for improved privacy",
                "NoInputNoOutput": "If possible, use devices with input or display capabilities for secure pairing"
            }
            
            issued_recommendations = set()
            for vuln in self.vulnerabilities:
                for key, rec in recommendations.items():
                    if key.lower() in vuln['description'].lower() and rec not in issued_recommendations:
                        print(f"- {rec}")
                        issued_recommendations.add(rec)
        else:
            print("- No specific recommendations - no vulnerabilities detected")
            
        print("\n===========================================")
        
        # Return data for potential saving to file
        return {
            'devices': self.devices,
            'vulnerabilities': self.vulnerabilities,
            'risk_score': self.risk_score
        }

    def save_report(self, output_format='csv'):
        """Save analysis results to file"""
        base_name = os.path.splitext(os.path.basename(self.pcap_file))[0]
        
        # Save devices info
        device_data = []
        for addr, info in self.devices.items():
            device_info = {'mac_address': addr}
            device_info.update({k: v for k, v in info.items() if not isinstance(v, set)})
            device_data.append(device_info)
        
        df_devices = pd.DataFrame(device_data)
        
        # Save vulnerabilities
        df_vulns = pd.DataFrame(self.vulnerabilities) if self.vulnerabilities else pd.DataFrame()
        
        if output_format == 'csv':
            if not df_devices.empty:
                df_devices.to_csv(f"{base_name}_devices.csv", index=False)
                logger.info(f"Devices report saved as {base_name}_devices.csv")
            if not df_vulns.empty:
                df_vulns.to_csv(f"{base_name}_vulnerabilities.csv", index=False)
                logger.info(f"Vulnerabilities report saved as {base_name}_vulnerabilities.csv")
        elif output_format == 'excel':
            with pd.ExcelWriter(f"{base_name}_report.xlsx") as writer:
                if not df_devices.empty:
                    df_devices.to_excel(writer, sheet_name='Devices', index=False)
                if not df_vulns.empty:
                    df_vulns.to_excel(writer, sheet_name='Vulnerabilities', index=False)
                
                # Create summary sheet
                summary = pd.DataFrame([{
                    'File': self.pcap_file,
                    'Packets Analyzed': self.packets_analyzed,
                    'Devices Found': len(self.devices),
                    'Vulnerabilities Found': len(self.vulnerabilities),
                    'Risk Score': self.risk_score
                }])
                summary.to_excel(writer, sheet_name='Summary', index=False)
            
            logger.info(f"Report saved as {base_name}_report.xlsx")

    def print_raw_packet_overview(self, limit=10):
        """Print raw packet overview for debugging"""
        try:
            print("\n--- RAW PACKET OVERVIEW (FOR DEBUGGING) ---")
            print(f"Showing first {limit} packets with protocol information:")
            
            cap = pyshark.FileCapture(self.pcap_file)
            count = 0
            
            for packet in cap:
                if count >= limit:
                    break
                    
                print(f"\nPacket #{count+1}:")
                print(f"  Layers: {[layer.layer_name for layer in packet.layers]}")
                
                # Try to identify the highest level protocol
                highest_protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"
                print(f"  Highest protocol: {highest_protocol}")
                
                # Look for any potentially useful fields
                for layer in packet.layers:
                    layer_fields = []
                    for field in dir(layer):
                        if not field.startswith('_') and field not in ['layer_name', 'get', 'get_field', 'get_field_by_showname']:
                            try:
                                value = getattr(layer, field)
                                if isinstance(value, str) and len(value) < 50:  # Only show reasonably sized values
                                    layer_fields.append(f"{field}={value}")
                            except:
                                pass
                    
                    if layer_fields:
                        print(f"  {layer.layer_name} fields: {', '.join(layer_fields[:5])}")
                
                count += 1
            
            if count == 0:
                print("No packets found in capture file")
            
        except Exception as e:
            print(f"Error printing packet overview: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Analyze Bluetooth packet captures for security issues')
    parser.add_argument('pcap_file', help='Path to the .pcapng file')
    parser.add_argument('-o', '--output', choices=['csv', 'excel'], default='csv', 
                        help='Output format for saved reports')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress console output')
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug information')
    
    args = parser.parse_args()
    
    if args.quiet:
        logger.setLevel(logging.WARNING)
    
    analyzer = BluetoothSecurityAnalyzer(args.pcap_file)
    analyzer.analyze()
    
    if args.debug:
        analyzer.print_raw_packet_overview()
        
    analyzer.generate_report()
    analyzer.save_report(args.output)


if __name__ == "__main__":
    main()
```

### Key Improvements:

1. **More Flexible Packet Detection**: 
   - Now checks for Bluetooth packets using multiple methods
   - Handles standard Bluetooth, Bluetooth Low Energy (BLE), and HCI packet formats
   - Falls back to looking for MAC addresses even if protocol-specific parsing fails

2. **Better Debugging**:
   - Added a debug mode that shows what kind of packets are in the capture file
   - Provides more detailed error messages when no packets are found

3. **More Robust Protocol Handling**:
   - Handles various Bluetooth protocol layers: BTHCI, BTATT, BTL2CAP, BTSMP, etc.
   - Specifically looks for BLE packets which might be missed by general filters

### Troubleshooting Steps:

If you're still having issues with the script showing zero packets, here are some steps to try:

1. First, verify your .pcapng file actually contains Bluetooth data:
   ```
   tshark -r your_capture.pcapng -T fields -e frame.protocols | grep -i blue
   ```

2. Try running the script with debug mode:
   ```
   python bluetooth_security_analyzer.py your_capture.pcapng --debug
   ```

3. Check if the capture uses a specific encapsulation format:
   ```
   tshark -r your_capture.pcapng -T fields -e frame.encap_type | head -1
   ```

4. If you're dealing with HCI (Host Controller Interface) logs rather than regular packet captures, you might need a specialized tool or to use a different approach.

Let me know if this script works better for your capture files!​​​​​​​​​​​​​​​​
