#!/bin/bash

# Bash script for better interaction with tcpdump and pcap files

# Load required libraries for GeoIP
if ! [ -x "$(command -v geoiplookup)" ]; thentCpDump.sh
  echo 'Error: geoiplookup is not installed.' >&2
  echo 'Please install geoip-bin package for GeoIP support.' >&2
  echo 'Continuing without GeoIP support...' >&2
  echo ""
  sleep 2
fi

# Function to display menu options
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
    read pcap_file

    if [ ! -f "$pcap_file" ]; then
        echo "File not found. Please try again."
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
        echo "14. Return to main menu"
        read -p "Option: " analysis_option

        case "$analysis_option" in
            1)
                tcpdump -r "$pcap_file" -nn
                ;;
            2)
                tcpdump -r "$pcap_file" -nn -n | awk '{print $3" -> "$5}' | sed 's/://'
                ;;

            3)
                tcpdump -r "$pcap_file" -nn -n | grep -E 'seq|ack' | awk '{print $1, $2, $3, $4, $5, $6, $7}'
                ;;
            4)
                tcpdump -r "$pcap_file" -nn -n | awk '{print $3" -> "$5}' | sed 's/://' | sort | uniq -c
                ;;

            5)
                tcpdump -r "$pcap_file" -nn -n | awk '{print $1}' | sort | uniq -c
                ;;
            6)
                tcpdump -r "$pcap_file" -nn -n | awk '{print $2}' | sort | uniq -c | sort -nr | head
                ;;
            7)
    if [ -x "$(command -v geoiplookup)" ]; then
        tcpdump -r "$pcap_file" -nn -n | awk '{print $2}' | sort | uniq | xargs -I % geoiplookup % | sort | uniq -c
    else
        echo "GeoIP analysis not available. Please install the geoip-bin package."
    fi
    ;;
8)
    tcpdump -r "$pcap_file" -nn -n port 53
    ;;
9)
    tcpdump -r "$pcap_file" -nn -n -A | grep -E '^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)'
    ;;
10)
    echo "Enter a custom BPF filter:"
    read custom_filter
    tcpdump -r "$pcap_file" -nn -n "$custom_filter"
    ;;
11)
    tcpdump -r "$pcap_file" -nn -n | awk '{print length($0)}' | sort -n | uniq -c
    ;;
12)
    tcpdump -r "$pcap_file" -nn -n | awk '{print $1, $5}' | sed 's/:/ /g' | awk '{print $1, $3}' | sort | uniq -c
    ;;
13)
    tcpdump -r "$pcap_file" -nn -n | grep -E "tcp.*(retransmission|duplicate)"
    ;;
14)
    break
    ;;
*)
    echo "Invalid analysis option. Please try again."
    ;;
esac

while true; do
    echo ""
    echo "1. Continue analysis"
    echo "2. Return to main menu"
    echo "3. Exit"
    read -p "Option: " continue_option

    case "$continue_option" in
        1)
            break
            ;;
        2)
            break 2
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
            ls *.pcap
            echo ""
            ;;
        2)
            analyze_pcap
            ;;
        3)
            man tcpdump | grep -A10 -e '^\s*-r' -e '^\s*-w' -e '^\s*-C' -e '^\s*-s' -e '^\s*-A' -e '^\s*-X'
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
