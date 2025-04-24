def _decode_l2cap_flags(flags_hex):
    """
    Decode L2CAP flags to extract security-related information
    
    Flags format in auth_req field:
    Bit 0: Bonding Flag (0 = No Bonding, 1 = Bonding)
    Bit 1: MITM (0 = Not Required, 1 = Required)
    Bit 2: SC - Secure Connections (0 = Not Required, 1 = Required)
    Bit 3: Keypress (0 = Not Used, 1 = Used)
    Bit 4: CT2 - Support for h7 function
    Bits 5-7: Reserved for future use
    
    Bonding flags (last two bits interpreted together):
    0b00 = No Bonding
    0b01 = Bonding
    0b10 = Reserved
    0b11 = Reserved
    """
    if not flags_hex:
        return {
            'bonding': 'Unknown',
            'mitm': 'Unknown',
            'secure_connections': 'Unknown',
            'keypress': 'Unknown',
            'ct2': 'Unknown',
            'raw_value': 'Unknown'
        }
    
    try:
        flags = int(flags_hex, 16)
        
        # Extract individual flags
        bonding_flag = flags & 0x01
        mitm_flag = (flags >> 1) & 0x01
        secure_connections_flag = (flags >> 2) & 0x01
        keypress_flag = (flags >> 3) & 0x01
        ct2_flag = (flags >> 4) & 0x01
        
        # Determine bonding type based on bonding bit
        bonding_type = "Bonding" if bonding_flag else "No Bonding"
        
        return {
            'bonding': bonding_type,
            'mitm': "Required" if mitm_flag else "Not Required",
            'secure_connections': "Required" if secure_connections_flag else "Not Required",
            'keypress': "Used" if keypress_flag else "Not Used",
            'ct2': "Supported" if ct2_flag else "Not Supported",
            'raw_value': flags_hex
        }
    except (ValueError, TypeError):
        return {
            'bonding': 'Error parsing',
            'mitm': 'Error parsing',
            'secure_connections': 'Error parsing',
            'keypress': 'Error parsing',
            'ct2': 'Error parsing',
            'raw_value': flags_hex
        }

def _decode_smp_auth_requirements(auth_req_hex):
    """
    Decode SMP authentication requirements flags
    
    Auth Requirements format (octet 6):
    Bit 0: Bonding Flags
    Bit 1: Bonding Flags
    Bit 2: MITM (0 = Not Required, 1 = Required)
    Bit 3: SC - Secure Connections (0 = Not Required, 1 = Required)
    Bit 4: Keypress (0 = Not Used, 1 = Used)
    Bit 5: CT2 - Support for h7 function
    Bits 6-7: Reserved for future use
    
    Bonding flags (bits 0-1):
    0b00 = No Bonding
    0b01 = Bonding
    0b10 = Reserved
    0b11 = Reserved
    """
    if not auth_req_hex:
        return {
            'bonding': 'Unknown',
            'mitm': 'Unknown',
            'secure_connections': 'Unknown',
            'keypress': 'Unknown',
            'ct2': 'Unknown',
            'raw_value': 'Unknown'
        }
    
    try:
        auth_req = int(auth_req_hex, 16)
        
        # Extract bonding flags (bits 0-1)
        bonding_flags = auth_req & 0x03
        if bonding_flags == 0:
            bonding = "No Bonding"
        elif bonding_flags == 1:
            bonding = "Bonding"
        else:
            bonding = f"Reserved (0x{bonding_flags:02X})"
        
        # Extract other flags
        mitm_flag = (auth_req >> 2) & 0x01
        secure_connections_flag = (auth_req >> 3) & 0x01
        keypress_flag = (auth_req >> 4) & 0x01
        ct2_flag = (auth_req >> 5) & 0x01
        
        return {
            'bonding': bonding,
            'mitm': "Required" if mitm_flag else "Not Required",
            'secure_connections': "Required" if secure_connections_flag else "Not Required",
            'keypress': "Used" if keypress_flag else "Not Used",
            'ct2': "Supported" if ct2_flag else "Not Supported",
            'raw_value': auth_req_hex
        }
    except (ValueError, TypeError):
        return {
            'bonding': 'Error parsing',
            'mitm': 'Error parsing',
            'secure_connections': 'Error parsing',
            'keypress': 'Error parsing',
            'ct2': 'Error parsing',
            'raw_value': auth_req_hex
        }

def _decode_smp_io_capability(io_cap_hex):
    """
    Decode SMP IO Capability value
    
    IO Capability values:
    0x00 = DisplayOnly
    0x01 = DisplayYesNo
    0x02 = KeyboardOnly
    0x03 = NoInputNoOutput (Just Works)
    0x04 = KeyboardDisplay
    """
    io_cap_mapping = {
        '0': 'DisplayOnly - Peripheral can display a 6-digit value',
        '1': 'DisplayYesNo - Peripheral can display and respond yes/no',
        '2': 'KeyboardOnly - Peripheral has keyboard input only',
        '3': 'NoInputNoOutput - No input and no output (Just Works)',
        '4': 'KeyboardDisplay - Peripheral has keyboard input and display',
        '0x00': 'DisplayOnly - Peripheral can display a 6-digit value',
        '0x01': 'DisplayYesNo - Peripheral can display and respond yes/no',
        '0x02': 'KeyboardOnly - Peripheral has keyboard input only',
        '0x03': 'NoInputNoOutput - No input and no output (Just Works)',
        '0x04': 'KeyboardDisplay - Peripheral has keyboard input and display'
    }
    
    if not io_cap_hex:
        return 'Unknown'
    
    # Remove 0x prefix if present
    io_cap_hex = io_cap_hex.replace('0x', '')
    
    return io_cap_mapping.get(io_cap_hex, f'Unknown IO Capability (0x{io_cap_hex})')

def _decode_smp_key_distribution(key_dist_hex):
    """
    Decode SMP key distribution flags
    
    Key Distribution format (octets 8 and 9):
    Bit 0: EncKey (Long Term Key)
    Bit 1: IdKey (Identity Key)
    Bit 2: Sign (CSRK - Connection Signature Resolving Key)
    Bit 3: LinkKey (BR/EDR Link Key derivation)
    Bits 4-7: Reserved
    """
    if not key_dist_hex:
        return {
            'enc_key': 'Unknown',
            'id_key': 'Unknown',
            'sign': 'Unknown',
            'link_key': 'Unknown',
            'raw_value': 'Unknown'
        }
    
    try:
        key_dist = int(key_dist_hex, 16)
        
        # Extract individual flags
        enc_key = (key_dist >> 0) & 0x01
        id_key = (key_dist >> 1) & 0x01
        sign = (key_dist >> 2) & 0x01
        link_key = (key_dist >> 3) & 0x01
        
        return {
            'enc_key': "LTK Distribution" if enc_key else "No LTK",
            'id_key': "IRK & Address Distribution" if id_key else "No IRK",
            'sign': "CSRK Distribution" if sign else "No CSRK",
            'link_key': "BR/EDR Link Key derivation" if link_key else "No BR/EDR Link Key",
            'raw_value': key_dist_hex
        }
    except (ValueError, TypeError):
        return {
            'enc_key': 'Error parsing',
            'id_key': 'Error parsing',
            'sign': 'Error parsing',
            'link_key': 'Error parsing',
            'raw_value': key_dist_hex
        }

def _decode_att_opcode(opcode_hex):
    """
    Decode ATT opcode and determine command type
    
    ATT opcodes:
    0x01-0x0B: Client->Server Commands
    0x01: ATT_READ_BY_TYPE_REQ
    0x02: ATT_READ_REQ
    0x03: ATT_READ_BLOB_REQ
    0x04: ATT_READ_MULTIPLE_REQ
    0x05: ATT_READ_BY_GROUP_TYPE_REQ
    0x06-0x0B: Other Client requests
    
    0x0A-0x0D: Read operations
    0x0A: ATT_READ_REQ (Read Request)
    0x0B: ATT_READ_RSP (Read Response)
    0x0C: ATT_READ_BLOB_REQ (Read Blob Request)
    0x0D: ATT_READ_BLOB_RSP (Read Blob Response)
    
    0x12-0x1D: Write operations
    0x12: ATT_WRITE_REQ (Write Request)
    0x13: ATT_WRITE_RSP (Write Response)
    0x16: ATT_PREPARE_WRITE_REQ (Prepare Write Request)
    0x17: ATT_PREPARE_WRITE_RSP (Prepare Write Response)
    0x18: ATT_EXECUTE_WRITE_REQ (Execute Write Request)
    0x19: ATT_EXECUTE_WRITE_RSP (Execute Write Response)
    0x1B: ATT_HANDLE_VALUE_NOTIFICATION (Handle Value Notification)
    0x1D: ATT_HANDLE_VALUE_INDICATION (Handle Value Indication)
    
    0x1E: ATT_HANDLE_VALUE_CONFIRMATION (Handle Value Confirmation)
    0x52: ATT_WRITE_COMMAND (Write Command - no confirmation needed)
    """
    att_opcodes = {
        '0x01': 'Exchange MTU Request',
        '0x02': 'Exchange MTU Response',
        '0x03': 'Find Information Request',
        '0x04': 'Find Information Response',
        '0x05': 'Find By Type Value Request',
        '0x06': 'Find By Type Value Response',
        '0x07': 'Read By Type Request',
        '0x08': 'Read By Type Response',
        '0x09': 'Read Request',
        '0x0A': 'Read Response',
        '0x0B': 'Read Blob Request',
        '0x0C': 'Read Blob Response',
        '0x0D': 'Read Multiple Request',
        '0x0E': 'Read Multiple Response',
        '0x0F': 'Read By Group Type Request',
        '0x10': 'Read By Group Type Response',
        '0x11': 'Write Request',
        '0x12': 'Write Response',
        '0x13': 'Write Command',
        '0x16': 'Prepare Write Request',
        '0x17': 'Prepare Write Response',
        '0x18': 'Execute Write Request',
        '0x19': 'Execute Write Response',
        '0x1B': 'Handle Value Notification',
        '0x1D': 'Handle Value Indication',
        '0x1E': 'Handle Value Confirmation',
        '0x52': 'Write Command (No confirmation)'
    }
    
    # Check if opcode is in hexadecimal format
    if not opcode_hex.startswith('0x'):
        opcode_hex = '0x' + opcode_hex
    
    # Return the operation type and description
    opcode_desc = att_opcodes.get(opcode_hex, f'Unknown Opcode: {opcode_hex}')
    
    # Determine operation type
    if opcode_hex in ['0x09', '0x0A', '0x0B', '0x0C', '0x0D', '0x0E']:
        op_type = 'Read'
    elif opcode_hex in ['0x11', '0x12', '0x13', '0x16', '0x17', '0x18', '0x19', '0x52']:
        op_type = 'Write'
    elif opcode_hex in ['0x1B', '0x1D', '0x1E']:
        op_type = 'Notification/Indication'
    else:
        op_type = 'Other'
    
    return {
        'opcode': opcode_hex,
        'description': opcode_desc,
        'type': op_type
    }

def _decode_att_permissions(perm_hex):
    """
    Decode ATT attribute permissions
    
    Attribute permissions (1 octet):
    Bit 0: Readable
    Bit 1: Writable
    Bit 2: Read requires authentication
    Bit 3: Write requires authentication
    Bit 4: Read requires authorization
    Bit 5: Write requires authorization
    Bit 6: Read requires encryption
    Bit 7: Write requires encryption
    """
    if not perm_hex:
        return {
            'readable': 'Unknown',
            'writable': 'Unknown',
            'read_auth': 'Unknown',
            'write_auth': 'Unknown',
            'read_author': 'Unknown',
            'write_author': 'Unknown',
            'read_encrypt': 'Unknown',
            'write_encrypt': 'Unknown',
            'raw_value': 'Unknown'
        }
    
    try:
        perm = int(perm_hex, 16)
        
        return {
            'readable': "Yes" if (perm & 0x01) else "No",
            'writable': "Yes" if (perm & 0x02) else "No",
            'read_auth': "Required" if (perm & 0x04) else "Not Required",
            'write_auth': "Required" if (perm & 0x08) else "Not Required",
            'read_author': "Required" if (perm & 0x10) else "Not Required",
            'write_author': "Required" if (perm & 0x20) else "Not Required",
            'read_encrypt': "Required" if (perm & 0x40) else "Not Required",
            'write_encrypt': "Required" if (perm & 0x80) else "Not Required",
            'raw_value': perm_hex
        }
    except (ValueError, TypeError):
        return {
            'readable': 'Error parsing',
            'writable': 'Error parsing',
            'read_auth': 'Error parsing',
            'write_auth': 'Error parsing',
            'read_author': 'Error parsing',
            'write_author': 'Error parsing',
            'read_encrypt': 'Error parsing',
            'write_encrypt': 'Error parsing',
            'raw_value': perm_hex
        }
