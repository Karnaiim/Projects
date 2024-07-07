#!/bin/bash

# Function to check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install missing forensics tools
install_forensics_tools() {
    local missing_tools=()

    # Check if each tool is available, add missing ones to the list
    if ! command_exists binwalk; then
        missing_tools+=(binwalk)
    fi
    if ! command_exists foremost; then
        missing_tools+=(foremost)
    fi
    if ! command_exists bulk_extractor; then
        missing_tools+=(bulk_extractor)
    fi
    if ! command_exists strings; then
        missing_tools+=(strings)
    fi

    # Check if Volatility (or 'vol') is available at the specified location
    local vol_path="/home/kali/Desktop/vol"
    if [ ! -x "$vol_path" ]; then
        echo "Volatility (or 'vol') not found in the specified location: $vol_path"
        echo "Please check the path."
        exit 1
    fi

    # Install missing tools if any
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "Installing missing forensics tools: ${missing_tools[*]}"
        sudo apt-get update
        sudo apt-get install -y "${missing_tools[@]}"
        echo "Installation complete."
    else
        echo "All forensics tools are already installed."
    fi
}

# Function to run binwalk on the specified filename
run_binwalk() {
    echo "Running binwalk on $filename..."

    local output_dir="./binwalk_output"
    mkdir -p "$output_dir"

    binwalk -C "$output_dir" "$filename" > "$output_dir/output.txt"
    echo "Binwalk output saved to: $output_dir/output.txt"

    create_report "binwalk" "$output_dir" "output.txt"
}

# Function to run bulk_extractor on the specified filename
run_bulk_extractor() {
    echo "Running bulk_extractor on $filename..."

    local output_dir="./bulk_extractor_output"
    mkdir -p "$output_dir"

    bulk_extractor -o "$output_dir" "$filename"
    display_pcap_details "$output_dir"

    create_report "bulk_extractor" "$output_dir"
}

# Function to display location and size of pcap file extracted by bulk_extractor
display_pcap_details() {
    local output_dir="$1"
    local pcap_file=$(find "$output_dir" -name "*.pcap" -print -quit)
    if [ -n "$pcap_file" ]; then
        local pcap_size=$(du -h "$pcap_file" | cut -f1)
        echo "PCAP file found at: $pcap_file"
        echo "PCAP file size: $pcap_size"
    else
        echo "No pcap file found in $output_dir."
    fi
}

# Function to run foremost on the specified filename
run_foremost() {
    echo "Running foremost on $filename..."

    local output_dir="./foremost_output"
    mkdir -p "$output_dir"

    foremost -o "$output_dir" -i "$filename"

    create_report "foremost" "$output_dir"
}

# Function to run strings on the specified filename
run_strings() {
    echo "Running strings on $filename..."

    local output_dir="./strings_output"
    mkdir -p "$output_dir"

    strings "$filename" > "$output_dir/strings_output.txt"
    echo "Strings output saved to: $output_dir/strings_output.txt"

    create_report "strings" "$output_dir" "strings_output.txt"
}

# Function to run volatility (or 'vol') on the specified memory dump
run_volatility() {
    local vol_path="/home/kali/Desktop/vol"

    echo "Running Volatility on $filename..."

    if [[ $filename != *.mem ]]; then
        echo "Error: $filename is not a .mem file. Exiting."
        exit 1
    fi

    local output_dir="./volatility_output"
    mkdir -p "$output_dir"

    PROFILE=$("$vol_path" -f "$filename" imageinfo 2>/dev/null | grep "Suggested" | awk '{print $4}' | awk -F "," '{print $1}')

    if [ -z "$PROFILE" ]; then
        echo "Error: Unable to determine Volatility profile. Exiting."
        exit 1
    fi

    echo "[*] Memory file Profile = $PROFILE"

    PLUGINS=("pstree" "connscan" "pslist" "hivelist" "printkey" "malfind")

    for plugin in "${PLUGINS[@]}"; do
        echo "[+] Running Volatility plugin: $plugin"
        "$vol_path" -f "$filename" --profile="$PROFILE" "$plugin" > "$output_dir/$plugin.txt" 2>/dev/null
    done

    echo "Volatility analysis complete. Results saved in $output_dir."

    create_report "volatility" "$output_dir"
}

# Function to create a report for each tool
create_report() {
    local tool="$1"
    local output_dir="$2"
    local output_file="${3:-}"

    local report_csv="$output_dir/report_${tool}.csv"
    local analysis_txt="$output_dir/analysis_report_${tool}.txt"

    local analysis_time=$(date)
    local total_files=$(find "$output_dir" -type f | wc -l)

    echo "Tool,Output Directory,Output File" > "$report_csv"
    echo "$tool,$output_dir,$output_file" >> "$report_csv"

    echo "Analysis Report for $tool" > "$analysis_txt"
    echo "Time of Analysis: $analysis_time" >> "$analysis_txt"
    echo "Total Files Found: $total_files" >> "$analysis_txt"

    echo "$tool report saved to: $report_csv and $analysis_txt"
}

# Function to zip the extracted files and the report, then clean up
zip_and_cleanup_results() {
    local zip_file="MemoryAnalysis_results.zip"
    zip -r "$zip_file" binwalk_output bulk_extractor_output foremost_output strings_output volatility_output > /dev/null
    echo "Zipped results saved to: $zip_file"

    # Remove the intermediate directories and files
    rm -rf binwalk_output bulk_extractor_output foremost_output strings_output volatility_output
    echo "Cleaned up intermediate files and directories."
}

# Function to display menu and handle user choice
display_menu() {
    echo "Select a tool to extract data:"
    echo "1. binwalk"
    echo "2. bulk_extractor"
    echo "3. foremost"
    echo "4. strings"
    echo "5. volatility (or 'vol')"
    read -p "Enter your choice (1/2/3/4/5): " choice

    case $choice in
        1) run_binwalk ;;
        2) run_bulk_extractor ;;
        3) run_foremost ;;
        4) run_strings ;;
        5) run_volatility ;;
        *) echo "Invalid choice. Please enter a number between 1 and 5." ;;
    esac

    zip_and_cleanup_results
}

# Main script execution
echo "You are root. Proceeding with script execution..."

# Check and install missing forensics tools
install_forensics_tools

# Prompt for filename input
read -p "Enter the filename: " filename

# Check if the file exists
if [ ! -f "$filename" ]; then
    echo "Error: File '$filename' does not exist."
    exit 1
fi

# Display menu to select tool and run the analysis
display_menu

echo "Analysis complete."
