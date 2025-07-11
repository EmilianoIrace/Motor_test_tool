#!/usr/bin/env python3
import logging
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from protocol_decoder_functions import (
    _decode_l2cap_flags,
    _decode_smp_auth_requirements,
    _decode_smp_io_capability,
    _decode_smp_key_distribution,
    _decode_att_opcode,
    _decode_att_permissions
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('BluetoothAnalyzer')

# Optional imports - will be used if available
try:
    import pyshark
except ImportError:
    logger.warning("pyshark module not found. Packet capture analysis will be limited.")
    pyshark = None

try:
    import pandas as pd
except ImportError:
    logger.warning("pandas module not found. Some reporting features will be limited.")
    pd = None

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
        
        # Track connection and pairing phases
        self.connection_phases = {}
        self.pairing_phases = {}
        self.smp_protocol_detected = set()  # Set of devices where SMP was detected
        self.att_protocol_detected = set()  # Set of devices where ATT was detected
        self.l2cap_protocol_detected = set()  # Set of devices where L2CAP was detected
        
        # Store detailed protocol packet information
        self.l2cap_packets = {}  # Detailed L2CAP packet information
        self.smp_packets = {}    # Detailed SMP packet information
        self.att_packets = {}    # Detailed ATT packet information
        
        # Enhanced security tracking
        self.e2e_encryption_detected = set()  # Set of devices with end-to-end encryption
        self.firmware_update_encryption = {}  # Track firmware update encryption status
        
    def analyze(self):
        """Main analysis function"""
        try:
            logger.info(f"Opening capture file: {self.pcap_file}")
            
            # Try with explicit SMP filter first to ensure we catch all SMP protocol activity
            smp_count = 0
            logger.info("Looking for SMP protocol packets...")
            try:
                smp_cap = pyshark.FileCapture(self.pcap_file, display_filter="btsmp")
                for packet in smp_cap:
                    smp_count += 1
                    device_mac = self._get_mac_from_packet(packet)
                    if device_mac:
                        logger.info(f"Found SMP packet for device: {device_mac}")
                        self.smp_protocol_detected.add(device_mac)
                        self._register_device(device_mac)
                        self.devices[device_mac]['smp_detected'] = True
                        # Process the SMP packet
                        self._process_packet(packet)
                logger.info(f"Found {smp_count} SMP protocol packets")
                # Close the capture when done to prevent event loop issues
                smp_cap.close()
                smp_cap = None
            except Exception as e:
                logger.warning(f"Error processing SMP packets: {str(e)}")
                # Ensure capture is closed even on error
                try:
                    if 'smp_cap' in locals() and smp_cap is not None:
                        smp_cap.close()
                        smp_cap = None
                except Exception:
                    pass
             # Continue with normal processing
            # Try different display filters to ensure we capture all Bluetooth traffic
            # Start with no filter to see all packets
            cap = None
            try:
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
                        
            except Exception as e:
                logger.warning(f"Error processing capture file: {str(e)}")
            finally:
                # Always close the capture to prevent event loop issues
                if cap:
                    cap.close()
                    cap = None
            
            # If no Bluetooth packets found, try with explicit BLE filter
            if self.packets_analyzed == 0:
                logger.info("No Bluetooth packets found with general filter. Trying BLE specific filter...")
                cap = None
                try:
                    cap = pyshark.FileCapture(self.pcap_file, display_filter="btle")
                    
                    for packet in cap:
                        try:
                            self.packets_analyzed += 1
                            if self.packets_analyzed % 100 == 0:
                                logger.info(f"Processed {self.packets_analyzed} BLE packets...")
                            
                            self._process_ble_packet(packet)
                        except Exception as e:
                            continue
                except Exception as e:
                    logger.warning(f"Error processing BLE packets: {str(e)}")
                finally:
                    # Always close the capture to prevent event loop issues
                    if cap:
                        cap.close()
                        cap = None
            
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
        cap = None
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
        finally:
            # Always close the capture to prevent event loop issues
            if cap:
                cap.close()
                cap = None
    
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
            
            # Specifically track SMP protocol usage
            if highest_layer == 'BTSMP' or 'SMP' in highest_layer:
                device_mac = self._get_mac_from_packet(packet)
                if device_mac:
                    self.smp_protocol_detected.add(device_mac)
                    if device_mac in self.devices:
                        self.devices[device_mac]['smp_detected'] = True
            
            # Specifically track ATT protocol usage
            if highest_layer == 'BTATT' or 'ATT' in highest_layer:
                device_mac = self._get_mac_from_packet(packet)
                if device_mac:
                    self.att_protocol_detected.add(device_mac)
                    if device_mac in self.devices:
                        self.devices[device_mac]['att_detected'] = True
            
            # Specifically track L2CAP protocol usage
            if highest_layer == 'BTL2CAP' or 'L2CAP' in highest_layer:
                device_mac = self._get_mac_from_packet(packet)
                if device_mac:
                    self.l2cap_protocol_detected.add(device_mac)
                    if device_mac in self.devices:
                        self.devices[device_mac]['l2cap_detected'] = True
        
        # Extract Bluetooth addresses from various layers
        for layer_name in dir(packet):
            if layer_name.startswith(('bthci', 'btatt', 'btsmp')):
                layer = getattr(packet, layer_name)
                self._extract_bt_info(layer, layer_name, timestamp)
                
                # Explicitly check for SMP layer
                if layer_name == 'btsmp':
                    # Make sure we record the device as having SMP
                    device_mac = self._get_mac_from_packet(packet)
                    if device_mac:
                        self.smp_protocol_detected.add(device_mac)
                        if device_mac in self.devices:
                            self.devices[device_mac]['smp_detected'] = True
            
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
            addr = None
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
            
            # Detect connection establishment phases
            if hasattr(packet.btle, 'advertising_header_pdu_type'):
                pdu_type = packet.btle.advertising_header_pdu_type
                
                # ADV_IND (0) - Connectable undirected advertising
                if pdu_type == '0':
                    if addr:
                        self._track_connection_phase(packet, 'advertisement', addr)
                
                # SCAN_REQ (2) - Scan request
                elif pdu_type == '2':
                    if addr:
                        self._track_connection_phase(packet, 'scan_request', addr)
                
                # SCAN_RSP (3) - Scan response
                elif pdu_type == '3':
                    if addr:
                        self._track_connection_phase(packet, 'scan_response', addr)
                
                # CONNECT_REQ (5) - Connection request
                elif pdu_type == '5':
                    if addr:
                        self._track_connection_phase(packet, 'connection_request', addr)
            
            # Check for HCI connection complete event
            if hasattr(packet, 'bthci_evt') and hasattr(packet.bthci_evt, 'code'):
                if packet.bthci_evt.code == '3e':  # LE Meta
                    if hasattr(packet.bthci_evt, 'le_meta_subevent'):
                        if packet.bthci_evt.le_meta_subevent == '1':  # LE Connection Complete
                            # Get the device address from the event
                            if hasattr(packet.bthci_evt, 'bd_addr'):
                                le_addr = packet.bthci_evt.bd_addr
                                self._track_connection_phase(packet, 'connection_complete', le_addr)
            
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
                self._analyze_advertising_data(packet, addr)
            
            # Check for GATT operations
            if hasattr(packet, 'btatt'):
                self._analyze_gatt_operations(packet, addr)
    
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
        """Enhanced firmware update detection"""
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
            
            if data:
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
            
            # Enhanced detection: Look for large data blocks (potential firmware chunks)
            if hasattr(packet, 'btatt') and hasattr(packet.btatt, 'value'):
                try:
                    value_len = len(bytes.fromhex(packet.btatt.value))
                    # Large chunks often signal firmware data
                    if value_len > 128:  
                        # Get the device
                        device_mac = self._get_mac_from_packet(packet)
                        if device_mac:
                            if 'large_data_transfers' not in self.devices[device_mac]:
                                self.devices[device_mac]['large_data_transfers'] = []
                            
                            self.devices[device_mac]['large_data_transfers'].append({
                                'size': value_len,
                                'packet_num': getattr(packet, 'number', 'unknown')
                            })
                            
                            # Multiple large transfers suggest firmware updates
                            if len(self.devices[device_mac]['large_data_transfers']) > 5:
                                self._register_vulnerability("Possible firmware update detected via large data transfers", 
                                                          device_mac, severity=3)
                except Exception:
                    pass
                    
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
        elif layer_name == 'btatt':
            # Track ATT protocol usage
            addr = None
            if hasattr(layer, 'src'):
                addr = layer.src
            elif hasattr(layer, 'dst'):
                addr = layer.dst
                
            if addr:
                self.att_protocol_detected.add(addr)
                if addr in self.devices:
                    self.devices[addr]['att_detected'] = True
                    
        elif layer_name == 'btl2cap':
            # Track L2CAP protocol usage and decode flags
            addr = None
            if hasattr(layer, 'src'):
                addr = layer.src
            elif hasattr(layer, 'dst'):
                addr = layer.dst
                
            if addr:
                self.l2cap_protocol_detected.add(addr)
                if addr in self.devices:
                    self.devices[addr]['l2cap_detected'] = True
                    # Get and decode L2CAP flags if present
                    if hasattr(layer, 'flags'):
                        flags = layer.flags
                        self.devices[addr]['l2cap_flags'] = flags
                        # Decode L2CAP flags and store in device info
                        decoded_flags = _decode_l2cap_flags(flags)
                        self.devices[addr]['decoded_l2cap_flags'] = decoded_flags
    
        elif layer_name == 'bthci_evt' and hasattr(layer, 'code'):
            self._extract_hci_evt_info(layer)
        elif layer_name == 'bthci_cmd' and hasattr(layer, 'opcode'):
            self._extract_hci_cmd_info(layer)
    
    def _extract_smp_info(self, layer):
        """Extract Security Manager Protocol information"""
        # Get device address - try multiple methods to identify the device
        addr = None
        if hasattr(layer, 'bd_addr'):
            addr = layer.bd_addr
        
        # Add to SMP detected devices if we have an address
        if addr:
            self.smp_protocol_detected.add(addr)
            # Ensure we record this in the device info too
            if addr in self.devices:
                self.devices[addr]['smp_detected'] = True
            
        # Identify SMP command code to track pairing process phases
        if hasattr(layer, 'opcode'):
            opcode = layer.opcode
            
            # Security Request (0x0B)
            if opcode == '0x0b' or opcode == '11':
                if addr:
                    self._track_pairing_phase(None, 'security_request', addr)
                    
                    # Check requested security level
                    if hasattr(layer, 'authentication'):
                        auth_flags = int(layer.authentication, 16)
                        self.pairing_phases[addr]['requested_security_level'] = auth_flags
            
            # Pairing Request (0x01)
            elif opcode == '0x01' or opcode == '1':
                if addr:
                    self._track_pairing_phase(None, 'pairing_request', addr)
                    
                    # Store pairing parameters
                    if hasattr(layer, 'io_capability'):
                        self.devices[addr]['pairing_method'] = layer.io_capability
                        
                    if hasattr(layer, 'oob_data_flag'):
                        self.pairing_phases[addr]['oob_data'] = layer.oob_data_flag
                        
                    if hasattr(layer, 'auth_req'):
                        self.pairing_phases[addr]['auth_requirements'] = layer.auth_req
                        
                    # Check for MITM protection
                    if hasattr(layer, 'auth_req'):
                        auth_req = int(layer.auth_req, 16)
                        mitm_flag = (auth_req & 0x04) != 0
                        self.pairing_phases[addr]['mitm_protection'] = mitm_flag
                        
                        if not mitm_flag:
                            self._register_vulnerability("No MITM protection in pairing request", 
                                                      addr, severity=4)
            
            # Pairing Response (0x02)
            elif opcode == '0x02' or opcode == '2':
                if addr:
                    self._track_pairing_phase(None, 'pairing_response', addr)
                    
                    # Check IO capability for pairing method
                    if hasattr(layer, 'io_capability'):
                        io_cap = layer.io_capability
                        self.pairing_phases[addr]['responder_io_capability'] = io_cap
                        
                        # Track authentication method
                        self.auth_methods[f"IO Capability: {io_cap}"] += 1
                        
                        # Check for Just Works pairing (vulnerable to MITM)
                        if io_cap == '0x03' or io_cap == '3':  # NoInputNoOutput
                            self._register_vulnerability("Using 'Just Works' pairing - vulnerable to MITM attacks", 
                                                      addr, severity=5)
            
            # Pairing Confirm (0x03) - indicates secure connection proceeding
            elif opcode == '0x03' or opcode == '3':
                if addr:
                    self.pairing_phases[addr]['pairing_confirm'] = True
                    self.security_events.append({
                        'type': 'pairing_confirm',
                        'device': addr
                    })
            
            # Encryption Information (0x06) - indicates LTK exchange
            elif opcode == '0x06' or opcode == '6':
                if addr:
                    self.pairing_phases[addr]['ltk_exchanged'] = True
                    self.pairing_phases[addr]['key_distribution'] = True
                    self._track_pairing_phase(None, 'key_distribution', addr)
                    self.devices[addr]['has_ltk'] = True
                    
                    self.security_events.append({
                        'type': 'ltk_exchange',
                        'device': addr
                    })
            
            # Identity Information (0x07) - indicates IRK exchange for privacy
            elif opcode == '0x07' or opcode == '7':
                if addr:
                    self.pairing_phases[addr]['irk_exchanged'] = True
                    self.security_events.append({
                        'type': 'irk_exchange',
                        'device': addr
                    })
                    
            # Identity Address Information (0x08)
            elif opcode == '0x08' or opcode == '8':
                if addr:
                    if hasattr(layer, 'identity_address_type'):
                        id_type = layer.identity_address_type
                        self.devices[addr]['identity_address_type'] = id_type
                        
                        if id_type == '0':  # Public address
                            self._register_vulnerability("Using public identity address with LTK - privacy concern", 
                                                      addr, severity=2)
                                                      
            # Signing Information (0x09) - indicates CSRK exchange
            elif opcode == '0x09' or opcode == '9':
                if addr:
                    self.pairing_phases[addr]['csrk_exchanged'] = True
                    self.security_events.append({
                        'type': 'csrk_exchange',
                        'device': addr
                    })
        
        # Check for long-term key presence from pre-existing code
        if hasattr(layer, 'ltk'):
            # Long Term Key present
            if addr:
                self.devices[addr]['has_ltk'] = True
                self.pairing_phases[addr]['ltk_exchanged'] = True
    
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
            
            # Check for security flags and decode them
            if hasattr(layer, 'authentication_requirements'):
                auth_req = layer.authentication_requirements
                self.devices[addr]['authentication_requirements'] = auth_req
                
                # Decode authentication requirements and store in device info
                if hasattr(self, '_decode_smp_auth_requirements'):
                    decoded_auth = _decode_smp_auth_requirements(auth_req)
                    self.devices[addr]['decoded_auth_requirements'] = decoded_auth
                
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
    
    def _assess_device_security(self, addr, device_info):
        """Perform comprehensive security assessment for a device"""
        assessment = {
            "encryption_status": "Encrypted" if device_info.get("encryption_enabled", False) else "Unencrypted",
            "pairing_security": "Unknown",
            "protocol_security": [],
            "recommendations": []
        }
        
        # Pairing security assessment
        if "pairing_method" in device_info:
            io_cap = device_info["pairing_method"]
            if io_cap in ["0x03", "3"]:
                assessment["pairing_security"] = "Low (Just Works)"
                assessment["recommendations"].append("Use a more secure pairing method with MITM protection")
            elif io_cap in ["0x01", "1"]:
                assessment["pairing_security"] = "Medium (Display Yes/No)"
            elif io_cap in ["0x04", "4"]:
                assessment["pairing_security"] = "High (Keyboard)"
        
        # Protocol security assessment
        if not device_info.get("encryption_enabled", False):
            assessment["recommendations"].append("Enable encryption for all communications")
        
        if device_info.get("encryption_key_size", 16) < 16:
            assessment["recommendations"].append(f"Increase encryption key size from {device_info.get('encryption_key_size')} to 16 bytes")
        
        # Privacy assessment
        if not device_info.get("uses_privacy", False):
            assessment["recommendations"].append("Use private random address instead of public address")
        
        # Service security assessment
        if "services" in device_info:
            for service in device_info["services"]:
                if any(s in service.lower() for s in ["1808", "1809", "1810", "183d"]):  # Health-related services
                    if not device_info.get("encryption_enabled", False):
                        assessment["recommendations"].append(f"Enable encryption for sensitive service {service}")
        
        return assessment
    
    def generate_report(self):
        """Generate comprehensive security analysis report"""
        report = {
            "summary": {
                "devices_found": len(self.devices),
                "vulnerabilities": len(self.vulnerabilities),
                "risk_score": self.risk_score,
                "packets_analyzed": self.packets_analyzed,
                "protocols": dict(self.protocols),
                "encryption_types": dict(self.encryption_types),
                "authentication_methods": dict(self.auth_methods)
            },
            "devices": {},
            "vulnerabilities": self.vulnerabilities,
            "communication_map": {addr: list(comms) for addr, comms in self.communication_map.items()},
            "security_events": self.security_events
        }
        
        # Add per-device detailed analysis
        for addr, device_info in self.devices.items():
            # Filter out set objects for JSON serialization
            device_report = {}
            for key, value in device_info.items():
                if isinstance(value, set):
                    device_report[key] = list(value)
                else:
                    device_report[key] = value
            
            # Add device vulnerabilities
            device_report["vulnerabilities"] = [
                v for v in self.vulnerabilities if v["device"] == addr
            ]
            
            # Add security assessment
            device_report["security_assessment"] = self._assess_device_security(addr, device_info)
            
            report["devices"][addr] = device_report
        
        return report
    
    def _get_mac_from_packet(self, packet):
        """Extract MAC address from a packet using various methods"""
        # Try different ways to get MAC addresses from various layers
        if hasattr(packet, 'bluetooth'):
            if hasattr(packet.bluetooth, 'src_bd_addr'):
                return packet.bluetooth.src_bd_addr
            if hasattr(packet.bluetooth, 'dst_bd_addr'):
                return packet.bluetooth.dst_bd_addr
        
        if hasattr(packet, 'btle'):
            if hasattr(packet.btle, 'advertising_address'):
                return packet.btle.advertising_address

        if hasattr(packet, 'btatt'):
            if hasattr(packet.btatt, 'src'):
                return packet.btatt.src
            if hasattr(packet.btatt, 'dst'):
                return packet.btatt.dst

        if hasattr(packet, 'btl2cap'):
            if hasattr(packet.btl2cap, 'src'):
                return packet.btl2cap.src
            if hasattr(packet.btl2cap, 'dst'):
                return packet.btl2cap.dst
            
        # Try to find MAC in the SMP layer
        if hasattr(packet, 'btsmp'):
            if hasattr(packet.btsmp, 'src'):
                return packet.btsmp.src
            if hasattr(packet.btsmp, 'dst'):
                return packet.btsmp.dst
            if hasattr(packet.btsmp, 'bd_addr'):
                return packet.btsmp.bd_addr
            
        # As a last resort, check any field that might contain a MAC
        for layer in packet.layers:
            for field in dir(layer):
                if 'addr' in field.lower() and not field.startswith('_'):
                    try:
                        value = getattr(layer, field)
                        if ':' in str(value) and len(str(value)) >= 12:
                            return value
                    except Exception:
                        continue
        
        return None
    
    def _analyze_protocol_versions(self):
        """Analyze Bluetooth protocol versions for vulnerabilities"""
        for protocol, versions in self.protocol_versions.items():
            for version, count in versions.items():
                # Check for known vulnerable versions
                if protocol == "BTL2CAP" and version < "0x08":  # L2CAP v8 introduced better security
                    for addr in self.devices:
                        if self.devices[addr].get('l2cap_detected', False):
                            self._register_vulnerability(
                                f"Using vulnerable L2CAP version {version}",
                                addr,
                                severity=4
                            )
                
                # BLE 4.0/4.1 have known issues
                if protocol == "BTLE" and version in ["4.0", "4.1"]:
                    for addr in self.devices:
                        if self.devices[addr].get('att_detected', False):
                            self._register_vulnerability(
                                f"Using vulnerable BLE version {version}",
                                addr,
                                severity=3
                            )
    
    def save_report(self, filename):
        """Save report to JSON file"""
        import json
        
        report = self.generate_report()
        
        # Convert sets to lists for JSON serialization
        for addr in report.get("devices", {}):
            for key, value in report["devices"][addr].items():
                if isinstance(value, set):
                    report["devices"][addr][key] = list(value)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        logger.info(f"Report saved to {filename}")

    @classmethod
    def from_report(cls, filename):
        """Create analyzer instance from a saved report"""
        import json
        
        with open(filename, 'r') as f:
            report = json.load(f)
        
        analyzer = cls("dummy.pcap")  # Create dummy instance
        
        # Populate with report data
        analyzer.devices = report.get("devices", {})
        analyzer.vulnerabilities = report.get("vulnerabilities", [])
        analyzer.risk_score = report.get("summary", {}).get("risk_score", 0)
        analyzer.packets_analyzed = report.get("summary", {}).get("packets_analyzed", 0)
        
        return analyzer
    
    def _track_connection_phase(self, packet, phase, device_addr=None):
        """
        Track the connection establishment phases for BLE devices
        Phases: Advertisement, Scan Request, Scan Response, Connection Request
        """
        if not device_addr:
            device_addr = self._get_mac_from_packet(packet)
            
        if not device_addr:
            return
            
        if device_addr not in self.connection_phases:
            self.connection_phases[device_addr] = {
                'advertisement': False,
                'scan_request': False,
                'scan_response': False,
                'connection_request': False,
                'connection_complete': False,
                'first_seen': getattr(packet, 'sniff_timestamp', None),
                'packet_numbers': {
                    'advertisement': [],
                    'scan_request': [],
                    'scan_response': [],
                    'connection_request': [],
                    'connection_complete': []
                }
            }
        
        self.connection_phases[device_addr][phase] = True
        packet_num = getattr(packet, 'number', 'unknown')
        if packet_num != 'unknown':
            self.connection_phases[device_addr]['packet_numbers'][phase].append(packet_num)
        
        # Record this as a security event for the timeline
        self.security_events.append({
            'type': f'connection_{phase}',
            'device': device_addr,
            'timestamp': getattr(packet, 'sniff_timestamp', None),
            'packet_num': packet_num
        })
        
        # If this is the connection complete event, we should note the connection handle
        if phase == 'connection_complete' and hasattr(packet, 'bthci_evt'):
            if hasattr(packet.bthci_evt, 'connection_handle'):
                self.devices[device_addr]['connection_handle'] = packet.bthci_evt.connection_handle
    
    def _track_pairing_phase(self, packet, phase, device_addr=None):
        """
        Track the pairing process phases for BLE devices
        Phases: Security Request, Pairing Request, Pairing Response, Key Distribution
        """
        if not device_addr:
            device_addr = self._get_mac_from_packet(packet)
            
        if not device_addr:
            return
            
        # Add device to SMP detected devices
        self.smp_protocol_detected.add(device_addr)
            
        if device_addr not in self.pairing_phases:
            self.pairing_phases[device_addr] = {
                'security_request': False,
                'pairing_request': False,
                'pairing_response': False,
                'key_distribution': False,
                'encryption_enabled': False,
                'ltk_exchanged': False,
                'irk_exchanged': False,
                'csrk_exchanged': False,
                'security_level': 0,
                'first_seen': getattr(packet, 'sniff_timestamp', None),
                'packet_numbers': {
                    'security_request': [],
                    'pairing_request': [],
                    'pairing_response': [],
                    'key_distribution': [],
                    'encryption_enabled': []
                }
            }
        
        self.pairing_phases[device_addr][phase] = True
        packet_num = getattr(packet, 'number', 'unknown')
        if packet_num != 'unknown':
            self.pairing_phases[device_addr]['packet_numbers'][phase].append(packet_num)
        
        # Record this as a security event for the timeline
        self.security_events.append({
            'type': f'pairing_{phase}',
            'device': device_addr,
            'timestamp': getattr(packet, 'sniff_timestamp', None),
            'packet_num': packet_num
        })
    
    def _identify_e2e_encryption(self):
        """
        Detect end-to-end (application layer) encryption in Bluetooth communications
        This is distinct from link-layer encryption handled by the BLE protocol
        """
        for addr, device_info in self.devices.items():
            # Check if the device is already using link-layer encryption
            if device_info.get('encryption_enabled', False):
                # Now look for additional encryption indicators
                
                # Method 1: Look for SSL/TLS traffic associated with the device
                if 'ssl_tls_version' in device_info:
                    self.e2e_encryption_detected.add(addr)
                    device_info['e2e_encryption'] = True
                    logger.info(f"Detected E2E encryption via SSL/TLS for device {addr}")
                
                # Method 2: Look for encrypted payloads in GATT values
                # Common patterns in encrypted data: high entropy, consistent headers, etc.
                if 'gatt_operations' in device_info:
                    encrypted_payload_indicators = 0
                    total_payloads = 0
                    
                    # If we have ATT value samples, analyze them for encryption patterns
                    if addr in self.att_packets and len(self.att_packets[addr]) > 5:
                        for att_data in self.att_packets[addr]:
                            if 'value' in att_data:
                                total_payloads += 1
                                value = att_data['value']
                                
                                # Check for high entropy (characteristic of encrypted data)
                                # Simple check: variety of byte values and lack of text patterns
                                try:
                                    if isinstance(value, str) and len(value) > 16:
                                        # Convert hex string to bytes if needed
                                        if all(c in '0123456789abcdefABCDEF' for c in value):
                                            try:
                                                value_bytes = bytes.fromhex(value)
                                            except ValueError:
                                                value_bytes = value.encode('utf-8')
                                        else:
                                            value_bytes = value.encode('utf-8')
                                        
                                        # Count unique bytes as a rough entropy measure
                                        unique_bytes = len(set(value_bytes))
                                        if unique_bytes > len(value_bytes) * 0.7:  # High unique byte ratio
                                            encrypted_payload_indicators += 1
                                except Exception:
                                    pass
                        
                        # If most payloads have encryption indicators
                        if total_payloads > 0 and (encrypted_payload_indicators / total_payloads) > 0.7:
                            self.e2e_encryption_detected.add(addr)
                            device_info['e2e_encryption'] = True
                            logger.info(f"Detected E2E encryption via payload analysis for device {addr}")
                
                # Method 3: Look for encryption handshake patterns in application data
                if 'large_data_transfers' in device_info:
                    # Check for characteristic patterns like key exchange
                    # For example, initial small packets (key exchange) followed by larger encrypted data
                    transfer_sizes = [t['size'] for t in device_info['large_data_transfers']]
                    if len(transfer_sizes) > 3:
                        # Pattern: small packets then consistently sized larger packets
                        if min(transfer_sizes[:2]) < 64 and max(transfer_sizes[2:]) > 128:
                            if len(set(s // 16 for s in transfer_sizes[2:])) < 3:  # Consistent block sizes
                                self.e2e_encryption_detected.add(addr)
                                device_info['e2e_encryption'] = True
                                logger.info(f"Detected E2E encryption via transfer patterns for device {addr}")
            
            # If we still haven't found E2E encryption but device has SMP with MITM protection
            # it could be using application-layer encryption not detected above
            if addr not in self.e2e_encryption_detected and addr in self.pairing_phases:
                if self.pairing_phases[addr].get('mitm_protection', False) and \
                   self.pairing_phases[addr].get('ltk_exchanged', False) and \
                   device_info.get('encryption_key_size', 0) >= 16:
                    
                    # High security connection might indicate E2E security too
                    device_info['potential_e2e_encryption'] = True
                    logger.info(f"Potential E2E encryption for high-security device {addr}")
        
        return self.e2e_encryption_detected
    
    def _verify_firmware_update_encryption(self):
        """
        Verify if firmware updates are encrypted and track findings 
        This provides deeper inspection than the basic firmware detection
        """
        for addr, device_info in self.devices.items():
            # Initialize tracking
            self.firmware_update_encryption[addr] = {
                'detected': False,
                'encrypted': False,
                'method': 'unknown',
                'confidence': 0  # 0-100% confidence in assessment
            }
            
            # First check if firmware update activity was detected
            has_dfu_service = device_info.get('has_dfu_service', False)
            has_firmware_activity = 'firmware_activity' in device_info
            has_large_transfers = 'large_data_transfers' in device_info and len(device_info.get('large_data_transfers', [])) > 3
            
            # If any update indicators are present
            if has_dfu_service or has_firmware_activity or has_large_transfers:
                self.firmware_update_encryption[addr]['detected'] = True
                
                # Start with base confidence based on evidence strength
                confidence = 0
                if has_dfu_service:
                    confidence += 30
                if has_firmware_activity:
                    confidence += 40
                if has_large_transfers:
                    confidence += 30
                
                # Now check for encryption
                if device_info.get('encryption_enabled', False):
                    # Link-layer encryption is enabled
                    self.firmware_update_encryption[addr]['encrypted'] = True
                    self.firmware_update_encryption[addr]['method'] = 'link-layer'
                    confidence = min(confidence + 20, 100)
                
                # Check for application-layer encryption
                if device_info.get('e2e_encryption', False) or device_info.get('potential_e2e_encryption', False):
                    self.firmware_update_encryption[addr]['encrypted'] = True
                    self.firmware_update_encryption[addr]['method'] = 'application-layer'
                    confidence = min(confidence + 30, 100)
                
                # Additional checks for firmware-specific encryption patterns
                if has_firmware_activity:
                    # Check first few bytes of firmware data for encryption signatures
                    # Common encryption headers include patterns like:
                    # - AES uses 16 byte blocks with high entropy
                    # - Some encrypted firmware includes specific headers
                    encryption_indicators = 0
                    
                    for activity in device_info.get('firmware_activity', []):
                        if 'data_sample' in activity and isinstance(activity['data_sample'], (bytes, bytearray)):
                            sample = activity['data_sample']
                            
                            # Check for high entropy in the data (characteristic of encryption)
                            if len(sample) >= 16:
                                # Calculate simple entropy (count of unique bytes / total length)
                                unique_bytes = len(set(sample[:64])) # Look at first 64 bytes
                                entropy = unique_bytes / min(64, len(sample))
                                
                                if entropy > 0.7:  # High entropy suggests encryption
                                    encryption_indicators += 1
                    
                    if encryption_indicators > 0:
                        self.firmware_update_encryption[addr]['encrypted'] = True
                        if self.firmware_update_encryption[addr]['method'] == 'unknown':
                            self.firmware_update_encryption[addr]['method'] = 'content-analysis'
                        confidence = min(confidence + 25, 100)
                
                # Look for OTA update services that specifically advertise encryption
                if 'advertised_services' in device_info:
                    secure_ota_uuids = [
                        'fe59',   # Nordic Secure DFU
                        '1530',   # Cypress Secure OTA
                        'fef5'    # Dialog Semiconductor Secure Service
                    ]
                    
                    for service in device_info.get('advertised_services', set()):
                        service = service.lower()
                        if any(uuid in service for uuid in secure_ota_uuids):
                            self.firmware_update_encryption[addr]['encrypted'] = True
                            self.firmware_update_encryption[addr]['method'] = 'secure-service'
                            confidence = min(confidence + 40, 100)
                
                # Set final confidence level
                self.firmware_update_encryption[addr]['confidence'] = confidence
                
                # Update device info with findings
                device_info['firmware_update_encrypted'] = self.firmware_update_encryption[addr]['encrypted']
                
                # Log findings
                if self.firmware_update_encryption[addr]['encrypted']:
                    logger.info(f"Firmware updates for {addr} appear to be encrypted via {self.firmware_update_encryption[addr]['method']} " +
                              f"(confidence: {confidence}%)")
                else:
                    # High severity vulnerability if firmware updates aren't encrypted
                    self._register_vulnerability("Firmware updates not using encryption",
                                               addr, severity=5)
                    logger.warning(f"Firmware updates for {addr} appear to be unencrypted (confidence: {confidence}%)")
        
        return self.firmware_update_encryption
    
    def generate_authentication_summary(self):
        """Generate a summary of authentication and pairing status for all devices"""
        summary = {
            'overall_findings': {
                'total_devices': len(self.devices),
                'devices_with_smp_detected': len(self.smp_protocol_detected),
                'devices_with_encryption': sum(1 for d in self.devices.values() if d.get('encryption_enabled', False)),
                'devices_without_pairing': sum(1 for d in self.devices.values() if not d.get('smp_detected', False)),
                'devices_without_encryption': sum(1 for d in self.devices.values() if not d.get('encryption_enabled', False))
            },
            'devices': {}
        }
        
        # Analyze each device
        for addr, device_info in self.devices.items():
            device_summary = {
                'device_name': device_info.get('device_name', 'Unknown Device'),
                'connection_established': False,
                'pairing_established': False,
                'encryption_enabled': device_info.get('encryption_enabled', False),
                'security_level': 0,  # 0-4 scale
                'connection_phases': {},
                'pairing_phases': {},
                'key_exchange': {
                    'ltk_exchanged': False,
                    'irk_exchanged': False,
                    'csrk_exchanged': False
                },
                'security_issues': []
            }
            
            # Check connection phases
            if addr in self.connection_phases:
                conn_phases = self.connection_phases[addr]
                device_summary['connection_established'] = any(
                    conn_phases.get(phase, False) for phase in 
                    ['connection_request', 'connection_complete']
                )
                device_summary['connection_phases'] = {
                    phase: conn_phases.get(phase, False) 
                    for phase in ['advertisement', 'scan_request', 'scan_response', 
                                'connection_request', 'connection_complete']
                }
            
            # Check pairing phases
            if addr in self.pairing_phases:
                pair_phases = self.pairing_phases[addr]
                device_summary['pairing_established'] = pair_phases.get('pairing_confirm', False)
                device_summary['pairing_phases'] = {
                    phase: pair_phases.get(phase, False)
                    for phase in ['security_request', 'pairing_request', 'pairing_response', 'key_distribution']
                }
                
                # Check key exchange status
                device_summary['key_exchange']['ltk_exchanged'] = pair_phases.get('ltk_exchanged', False)
                device_summary['key_exchange']['irk_exchanged'] = pair_phases.get('irk_exchanged', False)
                device_summary['key_exchange']['csrk_exchanged'] = pair_phases.get('csrk_exchanged', False)
            
            # Calculate security level
            if device_info.get('encryption_enabled', False):
                if pair_phases.get('mitm_protection', False) if addr in self.pairing_phases else False:
                    device_summary['security_level'] = 4  # Authenticated pairing with encryption
                else:
                    device_summary['security_level'] = 3  # Unauthenticated pairing with encryption
            elif device_summary['pairing_established']:
                device_summary['security_level'] = 2  # Pairing but no encryption
            elif device_summary['connection_established']:
                device_summary['security_level'] = 1  # Connected but no pairing
            
            # Collect security issues
            device_issues = [v for v in self.vulnerabilities if v['device'] == addr]
            device_summary['security_issues'] = [
                {'severity': issue['severity'], 'issue': issue['description']}
                for issue in device_issues
            ]
            
            summary['devices'][addr] = device_summary
        
        return summary

def main():
    """Command-line interface for Bluetooth Security Analyzer"""
    parser = argparse.ArgumentParser(description="Bluetooth Security Analyzer")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--output", "-o", help="Output file for JSON report", default="bt_security_report.json")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--auth-summary", "-a", action="store_true", help="Generate detailed authentication process summary")
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    analyzer = BluetoothSecurityAnalyzer(args.pcap_file)
    analyzer.analyze()
    
    report = analyzer.generate_report()
    
    # Print summary to console
    print("\n=== Bluetooth Security Analysis Summary ===")
    print(f"Devices found: {report['summary']['devices_found']}")
    print(f"Vulnerabilities: {report['summary']['vulnerabilities']}")
    print(f"Risk score: {report['summary']['risk_score']:.2f}/100")
    print(f"Packets analyzed: {report['summary']['packets_analyzed']}")
    
    # Generate authentication and pairing summary
    auth_summary = analyzer.generate_authentication_summary()
    
    print("\n=== Authentication Process Summary ===")
    print(f"Total devices: {auth_summary['overall_findings']['total_devices']}")
    print(f"Devices with SMP protocol detected: {auth_summary['overall_findings']['devices_with_smp_detected']}")
    print(f"Devices with encryption enabled: {auth_summary['overall_findings']['devices_with_encryption']}")
    print(f"Devices without proper pairing: {auth_summary['overall_findings']['devices_without_pairing']}")
    print(f"Devices without encryption: {auth_summary['overall_findings']['devices_without_encryption']}")
    
    # Print detailed pairing info for each device
    print("\n=== Device Authentication Details ===")
    for addr, device in auth_summary['devices'].items():
        print(f"\nDevice: {addr}")
        if device['device_name'] != 'Unknown Device':
            print(f"  Name: {device['device_name']}")
        
        # Connection phases
        print(f"  Connection established: {device['connection_established']}")
        if device['connection_established'] and device['connection_phases']:
            print("  Connection phases detected:")
            for phase, detected in device['connection_phases'].items():
                if detected:
                    print(f"    - {phase.replace('_', ' ').title()}")
        
        # Pairing info
        print(f"  Secure pairing established: {device['pairing_established']}")
        if device['pairing_established'] and device['pairing_phases']:
            print("  Pairing phases detected:")
            for phase, detected in device['pairing_phases'].items():
                if detected:
                    print(f"    - {phase.replace('_', ' ').title()}")
                    
        # Security level and encryption
        print(f"  Encryption enabled: {device['encryption_enabled']}")
        print(f"  Security level: {device['security_level']} (0-4, 4 is highest)")
        
        # Key exchange
        if any(device['key_exchange'].values()):
            print("  Keys exchanged:")
            for key_type, exchanged in device['key_exchange'].items():
                if exchanged:
                    print(f"    - {key_type.replace('_exchanged', '').upper()}")
        
        # Security issues
        if device['security_issues']:
            print("  Security issues:")
            for issue in device['security_issues']:
                print(f"    - [{issue['severity']}] {issue['issue']}")
    
    print("\n=== Top Vulnerabilities ===")
    for vuln in sorted(report['vulnerabilities'], key=lambda v: v['severity'], reverse=True)[:5]:
        print(f"[Severity {vuln['severity']}] {vuln['description']} - Device: {vuln['device']}")
    
    # Save detailed report to file
    analyzer.save_report(args.output)
    print(f"\nDetailed report saved to {args.output}")
    
    # Save authentication summary to a separate file if requested
    if args.auth_summary:
        # Save as CSV instead of JSON
        auth_output = args.output.replace('.json', '_auth_summary.csv')
        
        # Generate CSV for devices
        import csv
        with open(auth_output, 'w', newline='') as f:
            # Define CSV writer
            writer = csv.writer(f)
            
            # Write header row with more meaningful columns
            writer.writerow([
                'MAC Address', 
                'Device Name', 
                'Connection Type',
                'Pairing Status',
                'Encryption Status',
                'Security Level (0-4)', 
                'SMP Protocol',
                'ATT Protocol',
                'L2CAP Protocol',
                'Key Exchange',
                'Security Assessment',
                'Security Issues'
            ])
            
            # Write device data with more descriptive values
            for addr, device in auth_summary['devices'].items():
                # Combine security issues into a single string
                security_issues = "; ".join([f"{issue['severity']}: {issue['issue']}" 
                                           for issue in device['security_issues']])
                
                # Check if device address is in SMP detected set
                smp_detected = addr in analyzer.smp_protocol_detected
                
                # Check if device address is in ATT detected set
                att_detected = addr in analyzer.att_protocol_detected
                
                # Check if device address is in L2CAP detected set
                l2cap_detected = addr in analyzer.l2cap_protocol_detected
                
                # Create more human-readable output values
                connection_type = "Not Connected"
                if device['connection_established']:
                    connection_phases = []
                    for phase, detected in device.get('connection_phases', {}).items():
                        if detected:
                            connection_phases.append(phase.replace('_', ' ').title())
                    connection_type = f"Connected ({', '.join(connection_phases)})"
                
                pairing_status = "No Pairing"
                if device['pairing_established']:
                    pairing_status = "Secure Pairing Established"
                elif smp_detected:
                    pairing_status = "Pairing Attempted (Incomplete)"
                
                encryption_status = "Encrypted" if device['encryption_enabled'] else "UNENCRYPTED"
                
                # Describe key exchange
                key_exchange = []
                for key_type, exchanged in device.get('key_exchange', {}).items():
                    if exchanged:
                        key_exchange.append(key_type.replace('_exchanged', '').upper())
                key_exchange_str = ", ".join(key_exchange) if key_exchange else "No Keys Exchanged"
                
                # Create security assessment based on device details
                if device['security_level'] == 4:
                    security_assessment = "SECURE (Authenticated pairing with encryption)"
                elif device['security_level'] == 3:
                    security_assessment = "MODERATE (Unauthenticated pairing with encryption)"
                elif device['security_level'] == 2:
                    security_assessment = "LOW (Pairing without encryption)"
                elif device['security_level'] == 1:
                    security_assessment = "INSECURE (Connection without pairing)"
                else:
                    security_assessment = "UNKNOWN"
                
                writer.writerow([
                    addr,
                    device['device_name'],
                    connection_type,
                    pairing_status,
                    encryption_status,
                    device['security_level'],
                    "Detected" if smp_detected else "Not Detected",
                    "Detected" if att_detected else "Not Detected",
                    "Detected" if l2cap_detected else "Not Detected",
                    key_exchange_str,
                    security_assessment,
                    security_issues
                ])
        
        # Create a better organized summary CSV with authentication status
        summary_output = args.output.replace('.json', '_auth_summary_overview.csv')
        with open(summary_output, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Add informative headers
            writer.writerow(['Security Analysis Overview'])
            writer.writerow(['Generated on', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['PCAP File', analyzer.pcap_file])
            writer.writerow([])
            
            # Main metrics
            writer.writerow(['Key Security Metrics', 'Count', 'Percentage', 'Security Implication'])
            
            # Calculate percentages
            total_devices = auth_summary['overall_findings']['total_devices']
            smp_percent = 0
            encryption_percent = 0
            pairing_missing_percent = 0 
            encryption_missing_percent = 0
            
            if total_devices > 0:
                smp_percent = (auth_summary['overall_findings']['devices_with_smp_detected'] / total_devices) * 100
                encryption_percent = (auth_summary['overall_findings']['devices_with_encryption'] / total_devices) * 100
                pairing_missing_percent = (auth_summary['overall_findings']['devices_without_pairing'] / total_devices) * 100
                encryption_missing_percent = (auth_summary['overall_findings']['devices_without_encryption'] / total_devices) * 100
            
            # Write detailed metrics with security implications
            writer.writerow(['Total Devices', total_devices, '100%', 'Total devices detected in capture'])
            writer.writerow(['Devices with SMP Protocol', 
                          auth_summary['overall_findings']['devices_with_smp_detected'],
                          f"{smp_percent:.1f}%",
                          'SMP protocol indicates proper pairing intent'])
            writer.writerow(['Devices with Encryption Enabled', 
                          auth_summary['overall_findings']['devices_with_encryption'],
                          f"{encryption_percent:.1f}%", 
                          'Encrypted communication protects data from eavesdropping'])
            writer.writerow(['Devices Missing Proper Pairing', 
                          auth_summary['overall_findings']['devices_without_pairing'],
                          f"{pairing_missing_percent:.1f}%", 
                          'SECURITY RISK: Unauthorized devices can connect'])
            writer.writerow(['Devices Missing Encryption', 
                          auth_summary['overall_findings']['devices_without_encryption'],
                          f"{encryption_missing_percent:.1f}%",
                          'SECURITY RISK: Data can be intercepted'])
            
            # Add security assessment section
            writer.writerow([])
            writer.writerow(['Security Assessment'])
            
            # Overall security assessment based on findings
            if encryption_missing_percent > 50:
                writer.writerow(['Critical Security Risk', 'Most devices are operating without encryption'])
            elif encryption_missing_percent > 0:
                writer.writerow(['Significant Security Risk', 'Some devices are operating without encryption'])
            
            if pairing_missing_percent > 50:
                writer.writerow(['Critical Security Risk', 'Most devices lack proper authentication mechanism'])
            elif pairing_missing_percent > 0:
                writer.writerow(['Significant Security Risk', 'Some devices lack proper authentication mechanism'])
            
            if encryption_missing_percent == 0 and pairing_missing_percent == 0 and total_devices > 0:
                writer.writerow(['Secure Configuration', 'All detected devices use proper authentication and encryption'])
        
        print(f"Authentication summary saved to {auth_output}")
        print(f"Authentication overview saved to {summary_output}")
        
        # Create a detailed packet-level CSV with authentication and pairing information
        packets_output = args.output.replace('.json', '_auth_packets_detail.csv')
        with open(packets_output, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header row with Wireshark-like columns
            writer.writerow([
                'Packet No.',
                'Time',
                'Source',
                'Destination', 
                'Length',
                'Protocol',
                'Info',
                'Device MAC',
                'Authentication Phase',
                'Key Type'
            ])
            
            # Collect all relevant authentication and pairing packets
            relevant_events = []
            
            # Add connection establishment events
            for device_addr, phases in analyzer.connection_phases.items():
                for phase, detected in phases.items():
                    if phase != 'first_seen' and phase != 'packet_numbers' and detected:
                        for packet_num in phases['packet_numbers'].get(phase, []):
                            relevant_events.append({
                                'packet_no': packet_num,
                                'device_mac': device_addr,
                                'phase': f'Connection: {phase.replace("_", " ").title()}',
                                'key_type': ''
                            })
            
            # Add pairing events
            for device_addr, phases in analyzer.pairing_phases.items():
                for phase, detected in phases.items():
                    if phase not in ('first_seen', 'packet_numbers', 'ltk_exchanged', 'irk_exchanged', 
                                    'csrk_exchanged', 'security_level', 'mitm_protection', 
                                    'encryption_enabled', 'requested_security_level', 'pairing_confirm',
                                    'oob_data', 'auth_requirements', 'responder_io_capability') and detected:
                        for packet_num in phases['packet_numbers'].get(phase, []):
                            relevant_events.append({
                                'packet_no': packet_num,
                                'device_mac': device_addr,
                                'phase': f'Pairing: {phase.replace("_", " ").title()}',
                                'key_type': ''
                            })
            
            # Add key exchange events
            for device_addr, phases in analyzer.pairing_phases.items():
                if phases.get('ltk_exchanged', False):
                    relevant_events.append({
                        'packet_no': next(iter(phases['packet_numbers'].get('key_distribution', ['Unknown'])), 'Unknown'),
                        'device_mac': device_addr,
                        'phase': 'Key Exchange',
                        'key_type': 'LTK (Long Term Key)'
                    })
                if phases.get('irk_exchanged', False):
                    relevant_events.append({
                        'packet_no': next(iter(phases['packet_numbers'].get('key_distribution', ['Unknown'])), 'Unknown'),
                        'device_mac': device_addr,
                        'phase': 'Key Exchange',
                        'key_type': 'IRK (Identity Resolving Key)'
                    })
                if phases.get('csrk_exchanged', False):
                    relevant_events.append({
                        'packet_no': next(iter(phases['packet_numbers'].get('key_distribution', ['Unknown'])), 'Unknown'),
                        'device_mac': device_addr,
                        'phase': 'Key Exchange',
                        'key_type': 'CSRK (Connection Signature Resolving Key)'
                    })
            
            # Add all security events from analyzer
            for event in analyzer.security_events:
                if 'packet_num' in event and event['packet_num'] != 'unknown':
                    if event['type'].startswith(('pairing_', 'connection_', 'ltk_exchange', 'irk_exchange', 'csrk_exchange')):
                        # Extract phase from type
                        phase = event['type'].replace('_', ' ').title()
                        key_type = ''
                        
                        # Determine key type from event
                        if 'ltk' in event['type']:
                            key_type = 'LTK (Long Term Key)'
                        elif 'irk' in event['type']:
                            key_type = 'IRK (Identity Resolving Key)'
                        elif 'csrk' in event['type']:
                            key_type = 'CSRK (Connection Signature Resolving Key)'
                        
                        relevant_events.append({
                            'packet_no': event['packet_num'],
                            'device_mac': event['device'],
                            'phase': phase,
                            'key_type': key_type,
                            'timestamp': event.get('timestamp', '')
                        })
            
            # Sort by packet number 
            relevant_events.sort(key=lambda x: (
                int(x['packet_no']) if isinstance(x['packet_no'], str) and x['packet_no'].isdigit() else float('inf')
            ))
            
            # Re-read packets to get full Wireshark-like information
            packet_info_cache = {}
            
            try:
                # Re-read capture file to get detailed packet info
                cap = pyshark.FileCapture(analyzer.pcap_file)
                
                for packet in cap:
                    try:
                        packet_num = getattr(packet, 'number', 'unknown')
                        if packet_num != 'unknown':
                            # Cache packet information for use in CSV output
                            protocol = getattr(packet, 'highest_layer', '')
                            
                            # Get packet length
                            length = ""
                            if hasattr(packet, 'length'):
                                length = packet.length
                            elif hasattr(packet, 'frame_info'):
                                if hasattr(packet.frame_info, 'len'):
                                    length = packet.frame_info.len
                            
                            # Get source and destination
                            source = ""
                            destination = ""
                            
                            # Try different layers to get source/destination
                            if hasattr(packet, 'btle'):
                                if hasattr(packet.btle, 'advertising_address'):
                                    source = packet.btle.advertising_address
                                if hasattr(packet.btle, 'scanning_address'):
                                    destination = packet.btle.scanning_address
                            elif hasattr(packet, 'bluetooth'):
                                if hasattr(packet.bluetooth, 'src_bd_addr'):
                                    source = packet.bluetooth.src_bd_addr
                                if hasattr(packet.bluetooth, 'dst_bd_addr'):
                                    destination = packet.bluetooth.dst_bd_addr
                            elif hasattr(packet, 'btatt'):
                                if hasattr(packet.btatt, 'src'):
                                    source = packet.btatt.src
                                if hasattr(packet.btatt, 'dst'):
                                    destination = packet.btatt.dst
                            elif hasattr(packet, 'btl2cap'):
                                if hasattr(packet.btl2cap, 'src'):
                                    source = packet.btl2cap.src
                                if hasattr(packet.btl2cap, 'dst'):
                                    destination = packet.btl2cap.dst
                            
                            # Determine detailed protocol info
                            if hasattr(packet, 'btsmp') and protocol in ['BTSMP', 'SMP']:
                                protocol = 'BTSMP'
                                if hasattr(packet.btsmp, 'opcode'):
                                    # Map SMP opcodes to human-readable descriptions
                                    smp_opcodes = {
                                        '0': 'Reserved',
                                        '1': 'Pairing Request',
                                        '2': 'Pairing Response',
                                        '3': 'Pairing Confirm',
                                        '4': 'Pairing Random',
                                        '5': 'Pairing Failed',
                                        '6': 'Encryption Information (LTK)',
                                        '7': 'Identity Information (IRK)',
                                        '8': 'Identity Address Information',
                                        '9': 'Signing Information (CSRK)',
                                        '10': 'Security Request',
                                        '11': 'Pairing Public Key',
                                        '12': 'Pairing DHKey Check'
                                    }
                                    opcode = packet.btsmp.opcode.replace('0x', '')
                                    if opcode in smp_opcodes:
                                        protocol_info = smp_opcodes[opcode]
                                    else:
                                        protocol_info = f"SMP Opcode: {opcode}"
                                else:
                                    protocol_info = "SMP Protocol"
                            elif hasattr(packet, 'btle') and hasattr(packet.btle, 'advertising_header_pdu_type'):
                                protocol = 'BTLE'
                                # Map PDU types to human-readable descriptions
                                pdu_types = {
                                    '0': 'ADV_IND (Connectable undirected advertising)',
                                    '1': 'ADV_DIRECT_IND (Connectable directed advertising)',
                                    '2': 'SCAN_REQ (Scan request)',
                                    '3': 'SCAN_RSP (Scan response)',
                                    '4': 'CONNECT_REQ (Connect request)',
                                    '5': 'ADV_SCAN_IND (Scannable undirected advertising)',
                                    '6': 'ADV_NONCONN_IND (Non-connectable undirected advertising)'
                                }
                                pdu_type = packet.btle.advertising_header_pdu_type
                                if pdu_type in pdu_types:
                                    protocol_info = pdu_types[pdu_type]
                                else:
                                    protocol_info = f"PDU Type: {pdu_type}"
                            else:
                                protocol_info =protocol
                            
                            # Store in cache
                            packet_info_cache[packet_num] = {
                                'source': source,
                                'destination': destination,
                                'length': length,
                                'protocol': protocol,
                                'info': protocol_info,
                                'timestamp': getattr(packet, 'sniff_timestamp', '')
                            }
                    except Exception as e_inner:
                        logger.debug(f"Error caching packet info: {str(e_inner)}")
                        continue
            except Exception as e:
                logger.error(f"Error processing packets for CSV output: {str(e)}")
            finally:
                if 'cap' in locals() and cap:
                    cap.close()
            
            # Write events to CSV with more detailed information
            for event in relevant_events:
                packet_num = event.get('packet_no', 'unknown')
                packet_details = packet_info_cache.get(packet_num, {})
                
                # Determine protocol type based on packet info or event phase
                protocol = packet_details.get('protocol', '')
                if not protocol:
                    protocol = 'BTSMP' if 'Pairing' in event['phase'] or 'Key Exchange' in event['phase'] else 'BTLE'
                
                # Construct detailed info field
                info = packet_details.get('info', '')
                if not info:
                    info = f"{event['phase']} {event['key_type']}".strip()
                
                writer.writerow([
                    packet_num,
                    packet_details.get('timestamp', event.get('timestamp', '')),
                    packet_details.get('source', event.get('device_mac', '')),
                    packet_details.get('destination', ''),
                    packet_details.get('length', ''),
                    protocol,
                    info,
                    event['device_mac'],
                    event['phase'],
                    event['key_type']
                ])
        
        print(f"Authentication summary saved to {auth_output}")
        print(f"Authentication overview saved to {summary_output}")
        print(f"Packet-level authentication details saved to {packets_output}")


if __name__ == "__main__":
    main()

