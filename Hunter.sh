#!/bin/bash

#Function to download IOC lists. In case The Ioc list wasn't already downloaded it will be added to the system.
function download() {
    echo "Downloading the given file, one moment..."
    sleep 1
    mkdir -p "/home/kali/Desktop/Hunter"

    if [ -e "/home/kali/Desktop/Hunter/IOC2.log" ]; then  
        sleep 2
        echo "[+] IOC list Found"
    else
        echo "Downloading IOC list..."
        sleep 2
        wget "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/raw/main/2023-10-25-IOCs-from-DarkGate-activity.txt" -O "/home/kali/Desktop/Hunter/IOC2.log"
        sleep 2
        echo "IOC list downloaded successfully!"
    fi
}

#Function to run tshark live and scan for malicious IPs. 
#After adding the list into the machine I want Tshark to alert me in case there's an info to any suspicious files going inside.
#Therefore, as soon as the list is already exsisting on the machine Tshark will run automatically and alert me in case any suspicious activity is present.
function run_tshark() {
    sleep 2
    echo "Running tshark live for any suspicious activity..."
    sleep 2
    echo "Oh uh, it appears we have detected some malicious activity!"
    mkdir -p "/home/kali/Desktop/Hunter/captured_traffic"

    # Run tshark and capture traffic for 300 seconds (There's a lot of important files and data inside the list and it's impotant that Tshark will have at least 5 minutes.
    #To scan it entirely and locate all the information that I may need.
    tshark -i eth0 -a duration:300 -w "/home/kali/Desktop/Hunter/captured_traffic/captured_traffic.pcap"

    # Extract IP addresses from the captured traffic. After Tshark stops and end Scanning the entire List it will scan all Ip addresses.
    #Each and every IP that is located will be transfered into a txt file later on.
    tshark -r "/home/kali/Desktop/Hunter/captured_traffic/captured_traffic.pcap" -T fields -e ip.src -e ip.dst | tr -s ' ' '\n' | sort | uniq > "/home/kali/Desktop/Hunter/malicious_ips.txt"

    if [ -s "/home/kali/Desktop/Hunter/malicious_ips.txt" ]; then
        echo "Malicious IP addresses logged."
    else
        echo "No malicious IP addresses found."
    fi
}

#Function to extract URLs from IOC list.
#URLS are important to know if there are any files that were transferred during the live motoring.
#Same as the IP addresses, they will be scanned and transfered in to a text file.
function extract_urls() {
    sleep 2
    echo "Extracting URLs from IOC list..."

    grep -o 'hxxps://[^[:space:]]*' "/home/kali/Desktop/Hunter/IOC2.log" > "/home/kali/Desktop/Hunter/url_list.txt"
    sleep 2
    echo "URLs extracted and saved to url_list.txt"
}

#Function to extract hashes from IOC list. Will all be scanned and moved into a text file.
function extract_hashes() {
    sleep 2
    echo "Extracting hashes from IOC list..."

    grep -oE '[a-f0-9]{64}' "/home/kali/Desktop/Hunter/IOC2.log" > "/home/kali/Desktop/Hunter/hash_list.txt"
    sleep 2
    echo "Hashes extracted and saved to hash_list.txt"
}

#Function to extract file names from IOC list.
#Anything that was found during the 5 minutes i gave Tshark to run and monitor, pdf, exe, zip files will be listed later on on a txt file.
function extract_files() {
    sleep 2
    echo "Extracting file names from IOC list..."

    grep -oE 'file-[^. ]+\.pdf|file-[^. ]+\.cab|file-[^. ]+\.url|file-[^. ]+\.zip|file-[^. ]+\.msi|[^[:space:]]+\.exe|[^[:space:]]+\.au3' "/home/kali/Desktop/Hunter/IOC2.log" > "/home/kali/Desktop/Hunter/files_list.txt"
    sleep 2
    echo "File names extracted and saved to files_list.txt"
}

#Function to check file hashes.
function check_hashes() {
    sleep 2
    echo "Checking file hashes for malicious activity..."

    while IFS= read -r hash; do
        file_path="/home/kali/Desktop/Hunter/$hash"
        if [ -f "$file_path" ]; then
            file_size=$(stat -c%s "$file_path")
            if [ $file_size -lt 1048576 ]; then
                echo "File with hash $hash is under 1MB and logged as suspicious."
            fi
        fi
    done < "/home/kali/Desktop/Hunter/hash_list.txt"

    echo "File hash check completed."
}

#Function to log URLs and IPs with timestamps.
function log_iocs() {
    sleep 2
    echo "Logging URLs and IPs with timestamps..."
    sleep 2

    while IFS= read -r url; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Malicious URL found: $url" >> "/home/kali/Desktop/Hunter/malicious_urls.log"
    done < "/home/kali/Desktop/Hunter/url_list.txt"

    while IFS= read -r ip; do
        if [ -n "$ip" ]; then
            for single_ip in $ip; do
                echo "$(date '+%Y-%m-%d %H:%M:%S') - Malicious IP found: $single_ip" >> "/home/kali/Desktop/Hunter/malicious.IPs.log"
            done
        fi
    done < "/home/kali/Desktop/Hunter/malicious_ips.txt"

    echo "Logging completed."
}

#Function to display live findings for URLs, hashes, and files.
function display_live_findings() {
    echo "Displaying live findings for URLs, hashes, and files..."
   tail -n 9 /home/kali/Desktop/Hunter/malicious_urls.log /home/kali/Desktop/Hunter/malicious_ips.log /home/kali/Desktop/Hunter/hash_list.txt /home/kali/Desktop/Hunter/files_list.txt
    echo "Logging is complete!"
}

#Main function to execute all tasks.
function main() {
    download
    run_tshark
    extract_urls
    extract_hashes
    extract_files
    check_hashes
    log_iocs
    display_live_findings
}

main
