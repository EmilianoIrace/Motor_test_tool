import pyshark
from collections import Counter

def analyze_pcapng(file_path):
    cap = pyshark.FileCapture(file_path, display_filter='eth')

    mac_src_counter = Counter()
    mac_dst_counter = Counter()
    protocols_counter = Counter()

    security_flags = {
        "unencrypted_http": 0,
        "ftp_usage": 0,
        "telnet_usage": 0,
        "arp_spoofing": 0,
        "broadcast_traffic": 0,
        "dns_unencrypted": 0,
    }

    for pkt in cap:
        try:
            # Extract MAC addresses
            src_mac = pkt.eth.src
            dst_mac = pkt.eth.dst
            mac_src_counter[src_mac] += 1
            mac_dst_counter[dst_mac] += 1

            # Protocol detection
            if 'HTTP' in pkt:
                protocols_counter['HTTP'] += 1
                security_flags["unencrypted_http"] += 1

            if 'FTP' in pkt:
                protocols_counter['FTP'] += 1
                security_flags["ftp_usage"] += 1

            if 'TELNET' in pkt:
                protocols_counter['TELNET'] += 1
                security_flags["telnet_usage"] += 1

            if 'ARP' in pkt and pkt.arp.opcode == '2':
                protocols_counter['ARP'] += 1
                security_flags["arp_spoofing"] += 1

            if 'DNS' in pkt:
                protocols_counter['DNS'] += 1
                if 'TCP' not in pkt and 'TLS' not in pkt:
                    security_flags["dns_unencrypted"] += 1

            # Check for broadcast
            if dst_mac == 'ff:ff:ff:ff:ff:ff':
                security_flags["broadcast_traffic"] += 1

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
        'MAC Addresses Source': dict(mac_src_counter),
        'MAC Addresses Destination': dict(mac_dst_counter),
        'Protocols Detected': dict(protocols_counter),
        'Security Issues Found': security_flags,
        'Overall Safety Rating': safety_rating
    }

    return report

# Example usage
if __name__ == "__main__":
    filepath = "example.pcapng"
    results = analyze_pcapng(filepath)
    for category, info in results.items():
        print(f"\n{category}:\n{info}")
