import pyshark
from collections import Counter

def analyze_bluetooth_pcapng(file_path):
    cap = pyshark.FileCapture(file_path, display_filter='bluetooth')

    bt_addr_src_counter = Counter()
    bt_addr_dst_counter = Counter()
    protocols_counter = Counter()

    security_flags = {
        "unencrypted_bt_traffic": 0,
        "unknown_devices": 0,
        "pairing_requests": 0,
    }

    known_devices = set()  # Populate this with known Bluetooth addresses

    for pkt in cap:
        try:
            # Extract Bluetooth addresses
            src_addr = pkt.bluetooth.src
            dst_addr = pkt.bluetooth.dst
            bt_addr_src_counter[src_addr] += 1
            bt_addr_dst_counter[dst_addr] += 1

            # Check if addresses are known
            if src_addr not in known_devices or dst_addr not in known_devices:
                security_flags["unknown_devices"] += 1

            # Protocol detection
            if 'BTATT' in pkt:
                protocols_counter['ATT'] += 1
            if 'BTSMP' in pkt:
                protocols_counter['SMP'] += 1
                security_flags["pairing_requests"] += 1

            # Check for unencrypted traffic
            if 'BTLE' in pkt and hasattr(pkt, 'btle') and pkt.btle.encrypted == '0':
                security_flags["unencrypted_bt_traffic"] += 1

        except AttributeError:
            continue

    cap.close()

    # Safety Assessment
    risk_score = sum(security_flags.values())
    if risk_score == 0:
        safety_rating = "Secure"
    elif risk_score <= 5:
        safety_rating = "Moderate Risk"
    else:
        safety_rating = "High Risk"

    report = {
        'Bluetooth Addresses Source': dict(bt_addr_src_counter),
        'Bluetooth Addresses Destination': dict(bt_addr_dst_counter),
        'Protocols Detected': dict(protocols_counter),
        'Security Issues Found': security_flags,
        'Overall Safety Rating': safety_rating
    }

    return report

# Example usage
if __name__ == "__main__":
    filepath = "bluetooth_example.pcapng"
    results = analyze_bluetooth_pcapng(filepath)
    for category, info in results.items():
        print(f"\n{category}:\n{info}")
