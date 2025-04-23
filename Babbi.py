
#!/usr/bin/env python3
import pyshark
import argparse
import pandas as pd
from collections import defaultdict, Counter
import sys
import os
import logging

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
            cap = pyshark.FileCapture(self.pcap_file, display_filter="bluetooth")
            
            # Process each packet
            for packet in cap:
                self.packets_analyzed += 1
                if self.packets_analyzed % 1000 == 0:
                    logger.info(f"Processed {self.packets_analyzed} packets...")
                
                try:
                    self._process_packet(packet)
                except AttributeError:
                    continue
            
            # Generate reports after analysis
            self._calculate_risk_score()
            logger.info(f"Analysis complete - processed {self.packets_analyzed} packets")
            
        except FileNotFoundError:
            logger.error(f"File not found: {self.pcap_file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error analyzing capture: {str(e)}")
            sys.exit(1)
    
    def _process_packet(self, packet):
        """Process individual packets and extract information"""
        # Extract Bluetooth addresses
        if hasattr(packet, 'bthci_acl'):
            self._extract_acl_info(packet)
        elif hasattr(packet, 'bthci_cmd'):
            self._extract_cmd_info(packet)
        elif hasattr(packet, 'bthci_evt'):
            self._extract_evt_info(packet)
        elif hasattr(packet, 'btatt'):
            self._extract_att_info(packet)
        elif hasattr(packet, 'btsmp'):
            self._extract_smp_info(packet)
        
    def _extract_acl_info(self, packet):
        """Extract info from ACL packets"""
        if hasattr(packet.bthci_acl, 'src_bd_addr'):
            src_addr = packet.bthci_acl.src_bd_addr
            dst_addr = packet.bthci_acl.dst_bd_addr if hasattr(packet.bthci_acl, 'dst_bd_addr') else None
            
            self._register_device(src_addr)
            if dst_addr:
                self._register_device(dst_addr)
                self._register_connection(src_addr, dst_addr)
    
    def _extract_cmd_info(self, packet):
        """Extract info from HCI Command packets"""
        if hasattr(packet.bthci_cmd, 'bd_addr'):
            addr = packet.bthci_cmd.bd_addr
            self._register_device(addr)
            
            # Check for pairing commands
            if hasattr(packet.bthci_cmd, 'io_capability'):
                io_cap = packet.bthci_cmd.io_capability
                self.devices[addr]['io_capability'] = io_cap
                self.security_events.append({
                    'type': 'pairing_request',
                    'device': addr,
                    'io_capability': io_cap,
                    'timestamp': packet.sniff_timestamp
                })
                
                # Check for weak IO capability (potentially insecure pairing)
                if io_cap == '0x00':  # DisplayOnly
                    self._register_vulnerability("Device using DisplayOnly IO capability - susceptible to MITM", addr, severity=2)
                elif io_cap == '0x03':  # NoInputNoOutput
                    self._register_vulnerability("Device using NoInputNoOutput IO capability - susceptible to MITM", addr, severity=3)
    
    def _extract_evt_info(self, packet):
        """Extract info from HCI Event packets"""
        if hasattr(packet.bthci_evt, 'bd_addr'):
            addr = packet.bthci_evt.bd_addr
            self._register_device(addr)
            
            # Check encryption key size if available
            if hasattr(packet.bthci_evt, 'enc_key_size'):
                key_size = int(packet.bthci_evt.enc_key_size)
                self.devices[addr]['encryption_key_size'] = key_size
                
                # Flag weak encryption
                if key_size < 16:
                    self._register_vulnerability(f"Weak encryption key size ({key_size} bytes)", addr, severity=4)
    
    def _extract_att_info(self, packet):
        """Extract info from ATT protocol packets"""
        # Check for unencrypted sensitive operations
        if hasattr(packet, 'btatt'):
            if hasattr(packet.btatt, 'opcode'):
                opcode = packet.btatt.opcode
                
                # Check if sensitive operations are being performed
                sensitive_opcodes = ['0x12', '0x16', '0x18']  # Write, Prepare Write, Execute Write
                if opcode in sensitive_opcodes:
                    # Check if this happens before encryption is established
                    for addr in self.devices:
                        if not self.devices[addr].get('encryption_enabled', False):
                            self._register_vulnerability("Sensitive ATT operations without encryption", addr, severity=4)
    
    def _extract_smp_info(self, packet):
        """Extract Security Manager Protocol information"""
        if hasattr(packet, 'btsmp'):
            # Check pairing method
            if hasattr(packet.btsmp, 'io_capability'):
                io_cap = packet.btsmp.io_capability
                
                # Get device address from connection handle if possible
                addr = None
                for d_addr, d_info in self.devices.items():
                    if d_info.get('connection_handle') == getattr(packet, 'connection_handle', None):
                        addr = d_addr
                        break
                
                if addr:
                    self.devices[addr]['pairing_method'] = io_cap
                    
                    # Check for Just Works pairing (vulnerable to MITM)
                    if io_cap == '0x03':  # NoInputNoOutput
                        self._register_vulnerability("Using 'Just Works' pairing - vulnerable to MITM attacks", addr, severity=5)
    
    def _register_device(self, addr):
        """Register a device if not already tracked"""
        if addr not in self.devices:
            self.devices[addr] = {
                'packet_count': 0,
                'services': set(),
                'characteristics': set(),
                'encryption_enabled': False,
            }
        self.devices[addr]['packet_count'] += 1
    
    def _register_connection(self, src, dst):
        """Register a connection between devices"""
        if (src, dst) not in self.connections and (dst, src) not in self.connections:
            self.connections[(src, dst)] = {
                'packets': 0,
                'encrypted': False,
                'first_seen': None,
                'last_seen': None
            }
    
    def _register_vulnerability(self, description, device=None, severity=1):
        """Register a vulnerability with severity 1-5 (5 being most severe)"""
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
        print(f"\nFile analyzed: {self.pcap_file}")
        print(f"Total packets analyzed: {self.packets_analyzed}")
        print(f"Devices detected: {len(self.devices)}")
        
        # Device information
        print("\n--- DEVICES DETECTED ---")
        for addr, info in self.devices.items():
            print(f"\nMAC Address: {addr}")
            print(f"  Packet count: {info['packet_count']}")
            
            # Print any security-related information
            if 'io_capability' in info:
                print(f"  IO Capability: {info['io_capability']}")
            if 'encryption_key_size' in info:
                print(f"  Encryption Key Size: {info['encryption_key_size']} bytes")
            if 'encryption_enabled' in info:
                print(f"  Encryption Enabled: {info['encryption_enabled']}")
        
        # Vulnerabilities
        if self.vulnerabilities:
            print("\n--- SECURITY VULNERABILITIES ---")
            for vuln in sorted(self.vulnerabilities, key=lambda x: x['severity'], reverse=True):
                severity_text = '*' * vuln['severity'] 
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
        df_vulns = pd.DataFrame(self.vulnerabilities)
        
        if output_format == 'csv':
            df_devices.to_csv(f"{base_name}_devices.csv", index=False)
            if not df_vulns.empty:
                df_vulns.to_csv(f"{base_name}_vulnerabilities.csv", index=False)
            
            logger.info(f"Reports saved as {base_name}_devices.csv and {base_name}_vulnerabilities.csv")
        elif output_format == 'excel':
            with pd.ExcelWriter(f"{base_name}_report.xlsx") as writer:
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


def main():
    parser = argparse.ArgumentParser(description='Analyze Bluetooth packet captures for security issues')
    parser.add_argument('pcap_file', help='Path to the .pcapng file')
    parser.add_argument('-o', '--output', choices=['csv', 'excel'], default='csv', 
                        help='Output format for saved reports')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress console output')
    
    args = parser.parse_args()
    
    if args.quiet:
        logger.setLevel(logging.WARNING)
    
    analyzer = BluetoothSecurityAnalyzer(args.pcap_file)
    analyzer.analyze()
    analyzer.generate_report()
    analyzer.save_report(args.output)


if __name__ == "__main__":
    main()
```

This script provides a comprehensive analysis of Bluetooth communications captured in a .pcapng file, focusing on cybersecurity aspects. Here's what it does:

1. **Device Identification**: Extracts MAC addresses and device information from the packet capture
2. **Security Parameter Analysis**: Identifies:
   - Pairing methods used
   - Encryption capabilities
   - IO capabilities (which affect security)
3. **Vulnerability Detection**: Looks for:
   - "Just Works" pairing (vulnerable to MITM attacks)
   - Weak encryption key sizes
   - Unencrypted sensitive operations
4. **Risk Assessment**: Calculates an overall security score based on detected vulnerabilities
5. **Reporting**: Provides both console output and exportable reports in CSV or Excel format

### Usage Instructions:

1. Install required packages:
```
pip install pyshark pandas
```

2. Run the script on your .pcapng file:
```
python bluetooth_security_analyzer.py your_capture_file.pcapng
```

3. Additional options:
```
# Export to Excel instead of CSV
python bluetooth_security_analyzer.py your_capture_file.pcapng -o excel

# Suppress console output (only save files)
python bluetooth_security_analyzer.py your_capture_file.pcapng -q
```

The script will analyze the capture and provide a security assessment based on recognized Bluetooth security best practices. Would you like me to elaborate on any particular aspect of this script?​​​​​​​​​​​​​​​​
