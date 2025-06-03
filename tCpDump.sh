#!/bin/bash

# Bash script for enhanced interaction with tcpdump and pcap files

# Function to handle errors
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Check for required dependencies
command -v tcpdump >/dev/null 2>&1 || error_exit "tcpdump is not installed. Please install it."
if ! command -v geoiplookup >/dev/null 2>&1; then
    echo "Warning: geoiplookup is not installed. GeoIP support will be disabled." >&2
    echo "Please install geoip-bin package for GeoIP support." >&2
    sleep 2
fi

# Function to display main menu options
show_menu() {
    echo "Please choose an option:"
    echo "1. List available pcap files"
    echo "2. Analyze a pcap file"
    echo "3. Show tcpdump man page (related to pcap)"
    echo "4. Exit"
    echo ""
}

# Function to analyze pcap file with various analysis options
analyze_pcap() {
    echo "Enter the pcap file name:"
    read -r pcap_file

    if [ ! -f "$pcap_file" ] || [ ! -r "$pcap_file" ]; then
        echo "File not found or not readable. Please try again."
        return
    fi

    while true; do
        echo "Choose an analysis option:"
        echo "1. Basic analysis"
        echo "2. Show source and destination IPs"
        echo "3. Show conversation statistics (sequence and acknowledgement numbers)"
        echo "4. Show number of packets in each conversation"
        echo "5. Analyze protocol distribution"
        echo "6. Top talkers"
        echo "7. GeoIP analysis"
        echo "8. DNS query analysis"
        echo "9. HTTP request analysis"
        echo "10. Custom filtering"
        echo "11. Analyze packet size distribution"
        echo "12. Show list of used ports and associated services"
        echo "13. Display packet retransmissions"
        echo "14. Extract payload data"
        echo "15. Analyze TCP flags"
        echo "16. Export to CSV"
        echo "17. Detect anomalous traffic"
        echo "18. Visualize packet rate over time"
        echo "19. Analyze packet latency"
        echo "20. Identify unique devices (MAC addresses)"
        echo "21. Filter by time range"
        echo "22. Visualize conversation trace (graphical)"
        echo "24. Search for suspicious commands"
        echo "25. Return to main menu"
        read -p "Option: " analysis_option

        case "$analysis_option" in
            1)
                tcpdump -r "$pcap_file" -nn 2>/dev/null || echo "Error: Failed to read pcap file."
                ;;
            2)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $3" -> "$5}' | sed 's/://' || echo "Error: Failed to parse IPs."
                ;;
            3)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | grep -E 'seq|ack' | awk '{print $1, $2, $3, $4, $5, $6, $7}' || echo "Error: Failed to extract sequence/ack numbers."
                ;;
            4)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $3" -> "$5}' | sed 's/://' | sort | uniq -c || echo "Error: Failed to count packets."
                ;;
            5)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $1}' | sort | uniq -c || echo "Error: Failed to analyze protocols."
                ;;
            6)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -nr | head || echo "Error: Failed to identify top talkers."
                ;;
            7)
                if command -v geoiplookup >/dev/null 2>&1; then
                    tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $2}' | sort | uniq | while IFS= read -r ip; do
                        geoiplookup "$ip" 2>/dev/null
                    done | sort | uniq -c || echo "Error: Failed to perform GeoIP analysis."
                else
                    echo "GeoIP analysis not available. Please install the geoip-bin package."
                fi
                ;;
            8)
                tcpdump -r "$pcap_file" -nn -n port 53 2>/dev/null || echo "Error: Failed to analyze DNS queries."
                ;;
            9)
                tcpdump -r "$pcap_file" -nn -n -A 2>/dev/null | grep -E '^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)' || echo "Error: Failed to analyze HTTP requests."
                ;;
            10)
                echo "Enter a custom BPF filter (e.g., 'tcp port 80'):"
                read -r custom_filter
                if [ -z "$custom_filter" ]; then
                    echo "Error: No filter provided."
                else
                    tcpdump -r "$pcap_file" -nn -n "$custom_filter" 2>/dev/null || echo "Error: Invalid BPF filter or failed to apply."
                fi
                ;;
            11)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print length($0)}' | sort -n | uniq -c || echo "Error: Failed to analyze packet sizes."
                ;;
            12)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $1, $5}' | sed 's/:/ /g' | awk '{print $1, $3}' | sort | uniq -c || echo "Error: Failed to list ports."
                ;;
            13)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | grep -E "tcp.*(retransmission|duplicate)" || echo "No retransmissions found or error occurred."
                ;;
            14)
                tcpdump -r "$pcap_file" -nn -n -A 2>/dev/null | grep -A 5 -E '^[A-Z]+.*HTTP|^[0-9].*(\.|\:)' || echo "No payload data found or error occurred."
                ;;
            15)
                tcpdump -r "$pcap_file" -nn -n tcp 2>/dev/null | awk '/Flags/ {print $8}' | sort | uniq -c | sort -nr || echo "Error: Failed to analyze TCP flags."
                ;;
            16)
                echo "Enter output CSV file name (e.g., output.csv):"
                read -r csv_file
                if [ -z "$csv_file" ]; then
                    echo "Error: No file name provided."
                else
                    echo "Source IP,Destination IP,Protocol,Port" > "$csv_file"
                    tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $3","$5","$1","$5}' | sed 's/:/,/g' | awk -F',' '{print $1","$3","$5","$4}' >> "$csv_file" || echo "Error: Failed to export to CSV."
                    echo "Exported to $csv_file"
                fi
                ;;
            17)
                threshold=100
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $3}' | sort | uniq -c | awk -v thresh="$threshold" '$1 > thresh {print "Suspicious IP: " $2 " (" $1 " packets)"}' || echo "No anomalous traffic detected or error occurred."
                ;;
            18)
                tcpdump -r "$pcap_file" -nn -n 2>/dev/null | awk '{print $1}' | cut -d. -f1 | sort | uniq -c | awk '{print "Time: " $2 ", Packets: " $1}' || echo "Error: Failed to analyze packet rate."
                ;;
            19)
                tcpdump -r "$pcap_file" -nn -n -tt 2>/dev/null | awk 'NR>1 {print $1, ($1-prev)} {prev=$1}' | awk '$2>0 {print "Timestamp: " $1 ", Latency: " $2 " seconds"}' || echo "Error: Failed to analyze packet latency."
                ;;
            20)
                tcpdump -r "$pcap_file" -nn -e 2>/dev/null | awk '{print $2 "," $3}' | sort | uniq | while IFS=',' read -r src dst; do
                    echo "Source MAC: $src, Destination MAC: $dst"
                done || echo "Error: Failed to extract MAC addresses."
                ;;
            21)
                echo "Enter start time (Unix epoch, e.g., 1625097600):"
                read -r start_time
                echo "Enter end time (Unix epoch, e.g., 1625097660):"
                read -r end_time
                if [ -z "$start_time" ] || [ -z "$end_time" ]; then
                    echo "Error: Invalid time range."
                else
                    tcpdump -r "$pcap_file" -nn -n -tt "timestamp >= $start_time and timestamp <= $end_time" 2>/dev/null || echo "Error: Failed to filter by time range."
                fi
                ;;
            22)
                echo "Generating conversation trace chart..."
                temp_file=$(mktemp)
                tcpdump -r "$pcap_file" -nn -n -tt 2>/dev/null | awk '{print int($1) " " $3 " -> " $5}' | sed 's/://g' | sort | uniq -c | awk '{print $2 "," $3 "," $1}' > "$temp_file"
                
                timestamps=$(cut -d',' -f1 "$temp_file" | sort -u)
                conversations=$(awk -F',' '{print $2}' "$temp_file" | sort -u)
                datasets=""
                index=0
                colors=("rgba(75,192,192,1)" "rgba(255,99,132,1)" "rgba(54,162,235,1)" "rgba(255,205,86,1)")
                
                for conv in $conversations; do
                    data=$(awk -F',' -v c="$conv" '$2==c {print $3}' "$temp_file" | tr '\n' ',')
                    datasets="$datasets{\"label\":\"$conv\",\"data\":[$data],\"borderColor\":\"${colors[$index]}\",\"fill\":false},"
                    index=$((index + 1))
                done
                datasets="[${datasets%,}]"
                
                cat << EOF > chart_config
{
    "type": "line",
    "data": {
        "labels": [$(echo "$timestamps" | tr '\n' ',')],
        "datasets": $datasets
    },
    "options": {
        "scales": {
            "x": {"title": {"display": true, "text": "Time (Unix Epoch Seconds)"}},
            "y": {"title": {"display": true, "text": "Packet Count"}, "beginAtZero": true}
        },
        "plugins": {
            "title": {"display": true, "text": "Conversation Trace"}
        }
    }
}
EOF
                echo "Chart generated. See chart_config for Chart.js configuration."
                rm "$temp_file"
                ;;
            24)
                echo "Searching for suspicious commands (e.g., curl, wget, nc, bash)..."
                commands="curl|wget|nc|netcat|bash|sh|powershell|cmd.exe|whoami|ping|nslookup"
                tcpdump -r "$pcap_file" -nn -n -A 2>/dev/null | grep -Ei "$commands" -B 2 -A 2 | grep -E -v "^\s*$" || echo "No suspicious commands found or error occurred."
                echo ""
                echo "Note: Found commands may appear in User-Agent strings, URLs, or payloads. Review context for suspicion."
                ;;
            25)
                return
                ;;
            *)
                echo "Invalid analysis option. Please try again."
                ;;
        esac

        echo ""
        echo "1. Continue analysis"
        echo "2. Return to main menu"
        echo "3. Exit"
        read -p "Option: " continue_option

        case "$continue_option" in
            1)
                continue
                ;;
            2)
                return
                ;;
            3)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option. Please try again."
                ;;
        esac
    done
}

# Main script loop
while true; do
    show_menu
    read -p "Option: " option
    echo ""

    case "$option" in
        1)
            echo "Available pcap files:"
            find . -maxdepth 1 -type f \( -name "*.pcap" -o -name "*.pcapng" \) -exec basename {} \;
            echo ""
            ;;
        2)
            analyze_pcap
            ;;
        3)
            man tcpdump | grep -A10 -e '^\s*-r' -e '^\s*-w' -e '^\s*-C' -e '^\s*-s' -e '^\s*-A' -e '^\s*-X' || echo "Error: Failed to display man page."
            echo ""
            ;;
        4)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            echo ""
            ;;
    esac
done
