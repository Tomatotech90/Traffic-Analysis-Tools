import os
import json
from collections import defaultdict
from ipwhois import IPWhois
import re


def menu():
    print("\nMenu:")
    print("1. Analyze pcap file")
    print("2. Search for specific strings")
    print("3. Display geolocation of IP addresses")
    print("4. Extract files from pcap")
    print("5. Exit")


def analyze_pcap(pcap_file, output_file):
    print("Analyzing pcap file...")
    tshark_command = f'tshark -r "{pcap_file}" -T ek > "{output_file}"'
    os.system(tshark_command)
    print("Pcap file has been analyzed.")
    return process_output(output_file)


def search_strings_in_pcap(parsed_data, search_strings):
    print("Searching for specific strings...")

    for packet_idx, packet in enumerate(parsed_data):
        if 'layers' in packet and 'ip' in packet['layers']:
            src_ip = packet['layers']['ip']['ip_src']
            dst_ip = packet['layers']['ip']['ip_dst']
            info = packet['_source']['layers']['frame']['frame_info']

            found_strings = find_strings(packet, search_strings)
            if found_strings:
                for string, value in found_strings:
                    print(f"Packet #{packet_idx}: String: {string}, Src IP: {src_ip}, Destination: {dst_ip}, Info: {info}, Strings: {value}")


def display_geolocation(parsed_data):
    print("Displaying geolocation of IP addresses...")

    for packet_idx, packet in enumerate(parsed_data):
        if 'layers' in packet and 'ip' in packet['layers']:
            src_ip = packet['layers']['ip']['ip_src']
            dst_ip = packet['layers']['ip']['ip_dst']

            src_country = get_geolocation(src_ip)
            dst_country = get_geolocation(dst_ip)

            print(f"Packet #{packet_idx}: Src IP: {src_ip} ({src_country}), Destination: {dst_ip} ({dst_country})")


def extract_files(pcap_file):
    print("Extracting files from pcap...")
    output_dir = "extracted_files"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    tshark_command = f'tshark -r "{pcap_file}" --export-objects "http,{output_dir}"'
    os.system(tshark_command)
    print(f"Files have been extracted to the '{output_dir}' directory.")
 def detect_ddos(parsed_data, threshold=100):
    print("Detecting potential DDoS attacks...")

    src_ip_counter = defaultdict(int)

    for packet in parsed_data:
        if 'layers' in packet and 'ip' in packet['layers']:
            src_ip = packet['layers']['ip']['ip_src']
            src_ip_counter[src_ip] += 1

    potential_ddos_ips = {ip: count for ip, count in src_ip_counter.items() if count >= threshold}

    if potential_ddos_ips:
        print("Potential DDoS attacks detected from the following IP addresses:")
        for ip, count in potential_ddos_ips.items():
            print(f"IP: {ip}, Packets Sent: {count}")
    else:
        print("No potential DDoS attacks detected.")
        
        
       def analyze_suspicious_traffic(parsed_data, standard_ports=[80, 443]):
    print("Analyzing suspicious traffic...")

    for packet_idx, packet in enumerate(parsed_data):
        if 'layers' in packet and 'tcp' in packet['layers']:
            src_port = int(packet['layers']['tcp']['tcp_srcport'])
            dst_port = int(packet['layers']['tcp']['tcp_dstport'])

            if src_port not in standard_ports or dst_port not in standard_ports:
                print(f"Packet #{packet_idx}: Non-standard port detected (Src Port: {src_port}, Dst Port: {dst_port})")

def analyze_http_requests(parsed_data):
    print("Analyzing HTTP requests for potential web-based attacks...")

    sql_injection_pattern = re.compile(r"(?:\b(?:UNION|SELECT|INSERT|DELETE|UPDATE|DROP|ALTER)\b\s*(?:\b(?:ALL\b|DISTINCT\b)?\s*(?:\b\w+\b\s*,\s*)*\b\w+\b\s*(?:\b(?:FROM|INTO|WHERE|SET|VALUES|TABLE|DATABASE)\b)|\b(?:FROM|INTO|WHERE|SET|VALUES|TABLE|DATABASE)\b))", re.IGNORECASE)
    xss_pattern = re.compile(r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)", re.IGNORECASE)

    for packet_idx, packet in enumerate(parsed_data):
        if 'layers' in packet and 'http' in packet['layers']:
            http_payload = packet['layers']['http']

            if 'http_request_uri' in http_payload:
                uri = http_payload['http_request_uri']
                if sql_injection_pattern.search(uri) or xss_pattern.search(uri):
                    src_ip = packet['layers']['ip']['ip_src']
                    dst_ip = packet['layers']['ip']['ip_dst']
                    print(f"Packet #{packet_idx}: Potential web-based attack detected (Src IP: {src_ip}, Dst IP: {dst_ip}, URI: {uri})")
   


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
        choice = input("\nEnter your choice (1-8): ")

        if choice == '1':
            parsed_data = analyze_pcap(pcap_file, output_file)

        elif choice == '2':
            if parsed_data is None:
                print("Please analyze a pcap file first.")
            else:
                search_strings_in_pcap(parsed_data, search_strings)

        elif choice == '3':
            if parsed_data is None:
                print("Please analyze a pcap file first.")
            else:
                display_geolocation(parsed_data)

        elif choice == '4':
            extract_files(pcap_file)

        elif choice == '5':
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 5.")
        elif choice == '6':
            if parsed_data is None:
                print("Please analyze a pcap file first.")
                
         else:
              detect_ddos(parsed_data)
                 elif choice == '7':
            if parsed_data is None:
                print("Please analyze a pcap file first.")
            else:
                analyze_suspicious_traffic(parsed_data)

        elif choice == '8':
            if parsed_data is None:
                print("Please analyze a pcap file first.")
            else:
                analyze_http_requests(parsed_data)


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


def find_strings(packet, search_strings):
    found_strings = []
    for field in packet['layers']:
        for key, value in packet['layers'][field].items():
            for search_string in search_strings:
                if search_string.lower() in value.lower():
                    found_strings.append((search_string, value))

    return found_strings


def get_geolocation(ip):
    ipwhois = IPWhois(ip)
    try:
        result = ipwhois.lookup_rdap()
        return result.get('asn_country_code', 'Unknown')
    except Exception as e:
        print(f"Error getting geolocation for {ip}: {e}")
        return 'Unknown'
def menu():
    print("\nMenu:")
    print("1. Analyze pcap file")
    print("2. Search for specific strings")
    print("3. Display geolocation of IP addresses")
    print("4. Detect potential DDoS attacks")
    print("5. Extract files from pcap")
    print("6. Analyze suspicious traffic")
    print("7. Analyze HTTP requests for potential web-based attacks")
    print("9. Exit")

if __name__ == '__main__':
    main()
