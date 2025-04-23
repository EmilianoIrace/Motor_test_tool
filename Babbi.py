I'll enhance the script to provide a deeper analysis of each identified MAC address, focusing on the security aspects you mentioned. Here's an updated version that adds detailed inspection of protocols, encryption, authentication mechanisms, and potential vulnerabilities:

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
import re
import binascii

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BluetoothSecurityAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.devices = {}
        self.connections = defaultdict(dict)
        self.security_events = []
        self.vulnerabilities = []
        self.risk_score = 0
        self.packets_analyzed = 0
        
        # Protocol counters
        self.protocols = Counter()
        self.protocol_versions = defaultdict(Counter)
        self.encryption_types = Counter()
        self.auth_methods = Counter()
        
        # Firmware and update related data
        self.firmware_data = {}
        
        # Packet samples for each protocol
        self.protocol_samples = {}
        
        # SSL/TLS tracking
        self.ssl_connections = defaultdict(dict)
        
        # Track all device communication partners
        self.communication_map = defaultdict(set)
        
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
                        
                    # Check for any packet with source or destination MAC that matches our known devices
                    # Useful for detecting non-Bluetooth protocols used by the same device
                    if self.devices and hasattr(packet, 'eth'):
                        if hasattr(packet.eth, 'src') and packet.eth.src in self.devices:
                            self._analyze_non_bt_protocol(packet, packet.eth.src)
                        elif hasattr(packet.eth, 'dst') and packet.eth.dst in self.devices:
                            self._analyze_non_bt_protocol(packet, packet.eth.dst)
                            
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
                self._analyze_communication_patterns()
                self._identify_firmware_updates()
                self._check_for_vulnerabilities()
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
        
        # Track protocols used
        highest_layer = getattr(packet, 'highest_layer', None)
        if highest_layer:
            self.protocols[highest_layer] += 1
            
            # Store sample packet for each protocol (first 5)
            if highest_layer not in self.protocol_samples or len(self.protocol_samples[highest_layer]) < 5:
                if highest_layer not in self.protocol_samples:
                    self.protocol_samples[highest_layer] = []
                self.protocol_samples[highest_layer].append(str(packet))
        
        # Extract Bluetooth addresses from various layers
        for layer_name in dir(packet):
            if layer_name.startswith(('bthci', 'btatt', 'btsmp')):
                layer = getattr(packet, layer_name)
                self._extract_bt_info(layer, layer_name, timestamp)
            
            # Look for protocol version information
            if hasattr(layer_name, 'version'):
                self.protocol_versions[layer_name][getattr(layer_name, 'version')] += 1
        
        # Check for SSL/TLS
        if hasattr(packet, 'ssl') or hasattr(packet, 'tls'):
            self._analyze_ssl_tls(packet)
            
        # Check for specific services
        if hasattr(packet, 'btsdp'):
            self._analyze_service_discovery(packet)
        
        # Look for payload data that might indicate firmware updates
        self._check_for_firmware_data(packet)
    
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
            
            # Check for encrypted data
            if hasattr(packet.btle, 'data_header_llid'):
                # LLID of 3 often indicates encrypted data
                llid = packet.btle.data_header_llid
                if llid == '3':
                    for addr in self.devices:
                        if 'connection_handle' in self.devices[addr]:
                            self.devices[addr]['potential_encryption'] = True
            
            # Analyze advertising data
            if hasattr(packet.btle, 'advertising_data'):
                self._analyze_advertising_data(packet, addr if 'addr' in locals() else None)
            
            # Check for GATT operations
            if hasattr(packet, 'btatt'):
                self._analyze_gatt_operations(packet, addr if 'addr' in locals() else None)
    
    def _analyze_non_bt_protocol(self, packet, device_mac):
        """Analyze non-Bluetooth protocols used by known Bluetooth devices"""
        highest_layer = getattr(packet, 'highest_layer', None)
        if highest_layer:
            if 'other_protocols' not in self.devices[device_mac]:
                self.devices[device_mac]['other_protocols'] = Counter()
            
            self.devices[device_mac]['other_protocols'][highest_layer] += 1
            
            # Check for notable protocols
            if highest_layer in ['HTTP', 'DNS', 'MDNS', 'SSDP']:
                self._register_vulnerability(f"Device using cleartext protocol {highest_layer}", 
                                          device_mac, severity=3)
            
            # Check for IP connections
            if hasattr(packet, 'ip'):
                if 'ip_connections' not in self.devices[device_mac]:
                    self.devices[device_mac]['ip_connections'] = set()
                
                if hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
                    ip_pair = tuple(sorted([packet.ip.src, packet.ip.dst]))
                    self.devices[device_mac]['ip_connections'].add(ip_pair)
    
    def _analyze_advertising_data(self, packet, device_mac):
        """Analyze BLE advertising data for useful information"""
        try:
            if hasattr(packet.btle, 'advertising_data'):
                adv_data = packet.btle.advertising_data
                
                # Check for device name
                if hasattr(packet.btle, 'name'):
                    device_name = packet.btle.name
                    if device_mac:
                        self.devices[device_mac]['device_name'] = device_name
                
                # Look for service UUIDs
                for field in dir(packet.btle):
                    if 'uuid' in field.lower() and not field.startswith('_'):
                        uuid_value = getattr(packet.btle, field)
                        if device_mac:
                            if 'advertised_services' not in self.devices[device_mac]:
                                self.devices[device_mac]['advertised_services'] = set()
                            self.devices[device_mac]['advertised_services'].add(uuid_value)
                            
                            # Check for known vulnerable services
                            self._check_vulnerable_service(uuid_value, device_mac)
        except Exception as e:
            pass
    
    def _analyze_gatt_operations(self, packet, device_mac):
        """Analyze GATT operations for security issues"""
        try:
            if not hasattr(packet, 'btatt'):
                return
                
            # Check for read/write operations
            if hasattr(packet.btatt, 'opcode'):
                opcode = packet.btatt.opcode
                
                # Track operations per device
                if device_mac:
                    if 'gatt_operations' not in self.devices[device_mac]:
                        self.devices[device_mac]['gatt_operations'] = Counter()
                    self.devices[device_mac]['gatt_operations'][opcode] += 1
                
                # Check for writes without encryption/authentication
                if opcode in ['0x12', '0x16', '0x18']:  # Write, Prepare Write, Execute Write
                    # Get associated device
                    target_addr = None
                    if hasattr(packet.btatt, 'dst'):
                        target_addr = packet.btatt.dst
                    elif device_mac:
                        target_addr = device_mac
                    
                    if target_addr and target_addr in self.devices:
                        if not self.devices[target_addr].get('encryption_enabled', False):
                            # Check if it's writing to a sensitive handle
                            if hasattr(packet.btatt, 'handle'):
                                handle = int(packet.btatt.handle, 16)
                                if handle < 0x00FF:  # System handles are usually below this
                                    self._register_vulnerability("Write to sensitive GATT handle without encryption", 
                                                            target_addr, severity=4)
                                else:
                                    self._register_vulnerability("Unencrypted GATT writes", 
                                                            target_addr, severity=3)
                
                # Check for reads to potentially sensitive characteristics
                if opcode in ['0x0A', '0x0C']:  # Read, Read Blob
                    if hasattr(packet.btatt, 'handle'):
                        handle = int(packet.btatt.handle, 16)
                        if handle < 0x00FF:  # System handles
                            if device_mac and not self.devices.get(device_mac, {}).get('encryption_enabled', False):
                                self._register_vulnerability("Read from sensitive GATT handle without encryption", 
                                                        device_mac, severity=3)
        except Exception as e:
            pass
    
    def _analyze_ssl_tls(self, packet):
        """Analyze SSL/TLS traffic"""
        try:
            ssl_layer = getattr(packet, 'ssl', None) or getattr(packet, 'tls', None)
            if not ssl_layer:
                return
                
            # Get the device MAC if we can link it
            device_mac = None
            if hasattr(packet, 'eth'):
                src_mac = packet.eth.src
                dst_mac = packet.eth.dst
                if src_mac in self.devices:
                    device_mac = src_mac
                elif dst_mac in self.devices:
                    device_mac = dst_mac
            
            # Track SSL/TLS version
            if hasattr(ssl_layer, 'record_version'):
                version = ssl_layer.record_version
                self.protocol_versions['SSL/TLS'][version] += 1
                
                # Check for vulnerable versions
                if version in ['0x0301', '0x0300', '0x0002', '0x0001']:  # TLS 1.0, SSL 3.0, SSL 2.0, SSL 1.0
                    if device_mac:
                        self._register_vulnerability(f"Using vulnerable SSL/TLS version: {version}", 
                                                device_mac, severity=4)
                
                if device_mac:
                    self.devices[device_mac]['ssl_tls_version'] = version
            
            # Check for cipher suites
            if hasattr(ssl_layer, 'handshake_ciphersuite'):
                cipher = ssl_layer.handshake_ciphersuite
                
                # Check for weak ciphers
                weak_ciphers = ['0x0005', '0x0004', '0x0096', '0x0095', '0x0065', '0x0064']  # RC4, DES, etc.
                if cipher in weak_ciphers and device_mac:
                    self._register_vulnerability(f"Using weak SSL/TLS cipher: {cipher}", 
                                            device_mac, severity=4)
                
                if device_mac:
                    if 'ssl_ciphers' not in self.devices[device_mac]:
                        self.devices[device_mac]['ssl_ciphers'] = set()
                    self.devices[device_mac]['ssl_ciphers'].add(cipher)
        except Exception:
            pass
    
    def _analyze_service_discovery(self, packet):
        """Analyze SDP (Service Discovery Protocol) information"""
        try:
            if not hasattr(packet, 'btsdp'):
                return
                
            # Get device MAC
            device_mac = None
            if hasattr(packet.btsdp, 'bd_addr'):
                device_mac = packet.btsdp.bd_addr
            
            if not device_mac:
                return
                
            # Extract service information
            if hasattr(packet.btsdp, 'service_uuid'):
                service_uuid = packet.btsdp.service_uuid
                
                if 'services' not in self.devices[device_mac]:
                    self.devices[device_mac]['services'] = set()
                self.devices[device_mac]['services'].add(service_uuid)
                
                # Check for common services and their security implications
                self._check_vulnerable_service(service_uuid, device_mac)
        except Exception:
            pass
    
    def _check_vulnerable_service(self, service_uuid, device_mac):
        """Check if service UUID represents a potentially vulnerable service"""
        # Common UUIDs that might indicate security issues
        serial_uuids = ['1101', '1102', '1103', 'fff0', 'fff1', 'ff10']  # Serial Port related
        dfu_uuids = ['fe59', '1530', '1532']  # DFU/OTA update related  
        
        if any(uuid in service_uuid.lower() for uuid in serial_uuids):
            self._register_vulnerability("Using Serial Port Profile - potential for unencrypted data transfer", 
                                      device_mac, severity=2)
        
        if any(uuid in service_uuid.lower() for uuid in dfu_uuids):
            if device_mac and not self.devices.get(device_mac, {}).get('encryption_enabled', False):
                self._register_vulnerability("Potential unencrypted firmware update mechanism", 
                                          device_mac, severity=5)
            else:
                # Just note this for further investigation
                self.devices[device_mac]['has_dfu_service'] = True
    
    def _check_for_firmware_data(self, packet):
        """Check packet data for signs of firmware updates"""
        try:
            # Common firmware update signatures
            fw_signatures = [
                b'OTA', b'UPDATE', b'UPGRADE', b'FIRMWARE', b'FW_VER',
                bytes.fromhex('ff52fd00'),  # Some devices use this pattern
                bytes.fromhex('ff52fd01')
            ]
            
            # Check if we can extract binary data
            data = None
            if hasattr(packet, 'data'):
                try:
                    data = bytes.fromhex(packet.data.data_raw)
                except:
                    pass
            elif hasattr(packet, '_raw_packet'):
                try:
                    data = packet._raw_packet
                except:
                    pass
            
            if not data:
                return
                
            # Look for firmware signatures
            device_mac = None
            for sig in fw_signatures:
                if sig in data:
                    # Try to identify device
                    if hasattr(packet, 'bluetooth'):
                        if hasattr(packet.bluetooth, 'src_bd_addr'):
                            device_mac = packet.bluetooth.src_bd_addr
                        elif hasattr(packet.bluetooth, 'dst_bd_addr'):
                            device_mac = packet.bluetooth.dst_bd_addr
                    elif hasattr(packet, 'btle'):
                        if hasattr(packet.btle, 'advertising_address'):
                            device_mac = packet.btle.advertising_address
                    
                    if device_mac:
                        if 'firmware_activity' not in self.devices[device_mac]:
                            self.devices[device_mac]['firmware_activity'] = []
                        
                        self.devices[device_mac]['firmware_activity'].append({
                            'signature': sig.hex() if isinstance(sig, bytes) else sig,
                            'packet_num': getattr(packet, 'number', 'unknown'),
                            'timestamp': getattr(packet, 'sniff_timestamp', None)
                        })
                        
                        # Check if we can determine encryption status
                        if not self.devices[device_mac].get('encryption_enabled', False):
                            self._register_vulnerability("Potential unencrypted firmware update detected", 
                                                      device_mac, severity=5)
        except Exception:
            pass
    
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
                
                # Track authentication method
                self.auth_methods[f"IO Capability: {io_cap}"] += 1
                
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
                
                # Track if it's using a resolvable address for privacy
                if hasattr(layer, 'identity_address_type'):
                    id_type = layer.identity_address_type
                    self.devices[addr]['identity_address_type'] = id_type
                    
                    if id_type == '0':  # Public address
                        self._register_vulnerability("Using public identity address with LTK - privacy concern", 
                                                   addr, severity=2)
    
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
                        self.encryption_types["HCI Standard"] += 1
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
                
                # Track authentication method
                self.auth_methods[f"Auth Req: {auth_req}"] += 1
                
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
    
    def _analyze_communication_patterns(self):
        """Analyze communication patterns between devices"""
        # Build connection graph
        for addr, device_info in self.devices.items():
            # Check connection handles
            for other_addr, other_info in self.devices.items():
                if addr != other_addr:
                    if ('connection_handle' in device_info and 'connection_handle' in other_info and
                        device_info['connection_handle'] == other_info['connection_handle']):
                        self.communication_map[addr].add(other_addr)
                        self.communication_map[other_addr].add(addr)
            
            # Check if this device is communicating with many others (unusual for IoT)
            if len(self.communication_map[addr]) > 5:
                self._register_vulnerability(f"Device communicating with unusual number of partners ({len(self.communication_map[addr])})", 
                                         addr, severity=2)
    
    def _identify_firmware_updates(self):
        """Identify potential firmware update activities"""
        # Look for devices with firmware related services or activities
        for addr, device_info in self.devices.items():
            # Check for DFU/OTA related services
            if device_info.get('has_dfu_service') or 'firmware_activity' in device_info:
                # Check if there are large data transfers
                if device_info.get('packet_count', 0) > 100:
                    if not device_info.get('encryption_enabled', False):
                        self._register_vulnerability("Likely unencrypted firmware update activity", 
                                                  addr, severity=5)
                    else:
                        logger.info(f"Detected potential encrypted firmware update for device {addr}")
    
    def _check_for_vulnerabilities(self):
        """Check for additional vulnerabilities based on collected data"""
        # Check for devices that never enable encryption
        for addr, device_info in self.devices.items():
            if not device_info.get('encryption_enabled', False) and device_info.get('packet_count', 0) > 20:
                self._register_vulnerability("Device communicates without encryption", addr, severity=4)
            
            # Check for outdated protocol versions
            if 'ssl_tls_version' in device_info:
                version = device_info['ssl_tls_version']
                if version in ['0x0301', '0x0300']:  # TLS 1.0, SSL 3.0
                    self._register_vulnerability(f"Using outdated TLS/SSL version: {version}", addr, severity=4)
            
            # Check for devices advertising sensitive services without encryption
            if 'services' in device_info:
                sensitive_services = [
                    '1811',  # Alert Notification Service
                    '183D',  # Health Thermometer
                    '1828',  # Weight Scale
                    '1809',  # Health
                    '1810'   # Blood Pressure
                ]
                
                for service in device_info['services']:
                    if any(s in service for s in sensitive_services) and not device_info.get('encryption_enabled', False):
                        self._register_vulnerability(f"Sensitive service {service} offered without encryption", 
                                                  addr, severity=4)
    
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
        """Generate analysis​​​​​​​​​​​​​​​​
