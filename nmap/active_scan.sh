#!/bin/bash

# --- OS Fingerprinting Script ---
# This script runs Nmap's OS detection (-O) a specified
# number of times against a target and saves all
# results to a single output file.
#
# Usage: ./scan_os.sh <Target IP> <Iterations> <Output File>
# Example: ./scan_os.sh 192.168.1.1 5 os_results.txt
#
# IMPORTANT: Nmap's OS detection requires root privileges.
# You will likely need to run this script with sudo:
# sudo ./scan_os.sh 192.168.1.1 5 os_results.txt
# ---

# --- 1. Argument Validation ---

# Check if the correct number of arguments (exactly 3) was provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <Target IP> <Iterations> <Output File>"
    echo "Example: $0 192.168.1.1 5 os_results.txt"
    # Exit with an error code
    exit 1
fi

# --- 2. Assign Arguments to Variables ---

# Assign arguments to variables with clear names
TARGET_IP="$1"
ITERATIONS="$2"
OUTPUT_FILE="$3"

# --- 3. Display Plan to User ---

echo "Starting OS scan..."
echo "--------------------------------"
echo "Target IP:      $TARGET_IP"
echo "Iterations:     $ITERATIONS"
echo "Output File:    $OUTPUT_FILE"
echo "--------------------------------"
echo "Note: Nmap -O requires root. If the script hangs, it may be waiting for a sudo password."
echo ""

# --- 4. Main Scan Loop ---

# Loop from 1 up to the number of iterations specified
for (( i=1; i<=$ITERATIONS; i++ )); do
    
    echo "--- Starting Scan Run $i of $ITERATIONS ---"
    
    # Append a separator to the output file for readability
    echo "==========================================" >> "$OUTPUT_FILE"
    echo "           SCAN RUN $i / $ITERATIONS" >> "$OUTPUT_FILE"
    echo "           Timestamp: $(date)" >> "$OUTPUT_FILE"
    echo "==========================================" >> "$OUTPUT_FILE"
    
    # Run the nmap command
    # -O: Enable OS detection
    # -v: Verbose mode (optional, but good for seeing progress)
    # -A: Enable OS detection, version detection, script scanning, and traceroute
    # >>: Append output to the specified file
    # nmap -O -v "$TARGET_IP" >> "$OUTPUT_FILE"
    nmap -O --fuzzy "$TARGET_IP" >> "$OUTPUT_FILE"
    
    # Check if nmap command failed (e.g., target down)
    if [ $? -ne 0 ]; then
        echo "Warning: Nmap scan $i failed. Check $OUTPUT_FILE for details."
        echo "Nmap scan $i failed at $(date)" >> "$OUTPUT_FILE"
    fi
    
    echo "--- Finished Scan Run $i ---"

done

echo ""
echo "--------------------------------"
echo "All scans completed."
echo "Results saved to $OUTPUT_FILE"
echo "--------------------------------"