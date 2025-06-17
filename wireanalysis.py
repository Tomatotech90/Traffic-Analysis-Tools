import os
import json
import re
from collections import defaultdict, Counter
from ipwhois import IPWhois
import matplotlib.pyplot as plt


def menu():
    print("\nMenu:")
    print("1. Analyze pcap file")
    print("2. Search for specific strings")
    print("3. Display geolocation of IP addresses")
    print("4. Detect potential DDoS attacks")
    print("5. Extract files from pcap")
    print("6. Analyze suspicious traffic")
    print("7. Analyze HTTP requests")
    print("8. Show conversations")
    print("9. Show accessed paths")
    print("10. Brute-force attempt detection")
    print("11. Show top 5 talkers (chart)")
    print("12. Show DNS requests")
    print("13. Exit")


def analyze_pcap(pcap_file, output_file):
    print("Analyzing pcap file...")
    tshark_command = f'tshark -r "{pcap_file}" -T ek > "{output_file}"'
    os.system(tshark_command)
    print("Pcap file has been analyzed.")
    return process_output(output_file)


def process_output(output_file):
    with open(output_file, 'r') as f:
        data = f.readlines()
    parsed_data = []
    for line in data:
        try:
            parsed_line = json.loads(line.strip())
            parsed_data.append(parsed_line)
        except json.JSONDecodeError:
            continue
    return parsed_data


def get_geolocation(ip):
    ipwhois = IPWhois(ip)
    try:
        result = ipwhois.lookup_rdap()
        return result.get('asn_country_code', 'Unknown')
    except Exception as e:
        print(f"Error getting geolocation for {ip}: {e}")
        return 'Unknown'


def find_strings(packet, search_strings):
    found_strings = []
    for field in packet['layers']:
        for key, value in packet['layers'][field].items():
            for search_string in search_strings:
                if isinstance(value, str) and search_string.lower() in value.lower():
                    found_strings.append((search_string, value))
    return found_strings


def search_strings_in_pcap(parsed_data, search_strings):
    print("Searching for specific strings...")
    results = []
    for idx, packet in enumerate(parsed_data):
        if 'layers' in packet and 'ip' in packet['layers']:
            found = find_strings(packet, search_strings)
            if found:
                src = packet['layers']['ip']['ip_src']
                dst = packet['layers']['ip']['ip_dst']
                time = packet['_source']['layers']['frame']['frame_time']
                for keyword, value in found:
                    result = f"Packet #{idx}: Time: {time}, Src: {src}, Dst: {dst}, Keyword: {keyword}, Value: {value}"
                    print(result)
                    results.append(result)
    with open("string_search_results.txt", "w") as f:
        f.write("\n".join(results))
    print("Results saved to string_search_results.txt")


def display_geolocation(parsed_data):
    print("Displaying geolocation of IP addresses...")
    for idx, packet in enumerate(parsed_data):
        if 'layers' in packet and 'ip' in packet['layers']:
            src_ip = packet['layers']['ip']['ip_src']
            dst_ip = packet['layers']['ip']['ip_dst']
            print(f"Packet #{idx}: {src_ip} -> {dst_ip}")


def detect_ddos(parsed_data, threshold=100):
    print("Detecting DDoS...")
    counts = defaultdict(int)
    for packet in parsed_data:
        if 'ip' in packet['layers']:
            src_ip = packet['layers']['ip']['ip_src']
            counts[src_ip] += 1
    for ip, count in counts.items():
        if count > threshold:
            print(f"Potential DDoS from {ip}: {count} packets")


def extract_files(pcap_file):
    out_dir = "extracted_files"
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    os.system(f'tshark -r "{pcap_file}" --export-objects "http,{out_dir}"')
    print(f"Files saved to {out_dir}")


def analyze_suspicious_traffic(parsed_data):
    for idx, packet in enumerate(parsed_data):
        if 'tcp' in packet['layers']:
            src_port = int(packet['layers']['tcp']['tcp_srcport'])
            dst_port = int(packet['layers']['tcp']['tcp_dstport'])
            if src_port not in [80, 443] and dst_port not in [80, 443]:
                print(f"Packet #{idx}: Suspicious port {src_port} -> {dst_port}")


def analyze_http_requests(parsed_data):
    sql = re.compile(r"(SELECT|UNION|DROP|INSERT|DELETE)", re.IGNORECASE)
    xss = re.compile(r"(<script>|%3Cscript%3E)", re.IGNORECASE)
    for idx, packet in enumerate(parsed_data):
        if 'http' in packet['layers'] and 'http_request_uri' in packet['layers']['http']:
            uri = packet['layers']['http']['http_request_uri']
            if sql.search(uri) or xss.search(uri):
                print(f"Packet #{idx}: Suspicious URI -> {uri}")


def show_conversations(parsed_data):
    for idx, packet in enumerate(parsed_data):
        if 'ip' in packet['layers']:
            src = packet['layers']['ip']['ip_src']
            dst = packet['layers']['ip']['ip_dst']
            time = packet['_source']['layers']['frame']['frame_time']
            print(f"Packet #{idx}: {src} -> {dst} @ {time}")


def show_accessed_paths(parsed_data):
    for idx, packet in enumerate(parsed_data):
        if 'http' in packet['layers'] and 'http_request_uri' in packet['layers']['http']:
            uri = packet['layers']['http']['http_request_uri']
            src = packet['layers']['ip']['ip_src']
            time = packet['_source']['layers']['frame']['frame_time']
            print(f"Packet #{idx}: Path {uri} accessed by {src} @ {time}")


def detect_brute_force(parsed_data):
    attempts = Counter()
    for packet in parsed_data:
        if 'tcp' in packet['layers']:
            src_ip = packet['layers']['ip']['ip_src']
            dst_port = int(packet['layers']['tcp']['tcp_dstport'])
            if dst_port in [22, 23, 21, 445]:
                attempts[src_ip] += 1
    for ip, count in attempts.items():
        if count > 10:
            print(f"Brute-force suspicion: {ip} attempted {count} connections")


def top_talkers(parsed_data):
    talkers = Counter()
    for packet in parsed_data:
        if 'ip' in packet['layers']:
            talkers[packet['layers']['ip']['ip_src']] += 1
    ips, counts = zip(*talkers.most_common(5))
    plt.bar(ips, counts)
    plt.title("Top 5 Talkers")
    plt.xlabel("IP Address")
    plt.ylabel("Packet Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("top_talkers_chart.png")
    print("Chart saved as top_talkers_chart.png")


def show_dns_requests(parsed_data):
    for idx, packet in enumerate(parsed_data):
        if 'dns' in packet['layers'] and 'dns_qry_name' in packet['layers']['dns']:
            qry = packet['layers']['dns']['dns_qry_name']
            src = packet['layers']['ip']['ip_src']
            print(f"Packet #{idx}: DNS Query for {qry} from {src}")


def main():
    pcap_file = 'input.pcap'
    output_file = 'output.json'
    parsed_data = None
    search_strings = [
        'password', 'username', 'login', 'email', 'user', 'credentials', 'token', 'auth',
        'flag', 'key', 'secret', 'encryption', 'decryption', 'cipher', 'hash', 'signature',
        'cert', 'certificate', 'private_key', 'public_key'
    ]

    while True:
        menu()
        choice = input("\nEnter your choice (1-13): ")

        if choice == '1':
            parsed_data = analyze_pcap(pcap_file, output_file)
        elif choice == '2':
            if parsed_data:
                search_strings_in_pcap(parsed_data, search_strings)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '3':
            if parsed_data:
                display_geolocation(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '4':
            if parsed_data:
                detect_ddos(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '5':
            extract_files(pcap_file)
        elif choice == '6':
            if parsed_data:
                analyze_suspicious_traffic(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '7':
            if parsed_data:
                analyze_http_requests(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '8':
            if parsed_data:
                show_conversations(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '9':
            if parsed_data:
                show_accessed_paths(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '10':
            if parsed_data:
                detect_brute_force(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '11':
            if parsed_data:
                top_talkers(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '12':
            if parsed_data:
                show_dns_requests(parsed_data)
            else:
                print("Please analyze the pcap file first.")
        elif choice == '13':
            break
        else:
            print("Invalid choice.")


if __name__ == '__main__':
    main()
