#!/bin/bash

# Source: https://github.com/TheOpenCanaryExperience/Scripts-Tips-and-Tricks
# Credit: Scripts created from instructions to ChatGPT (why not?!)
# Based on: https://github.com/thinkst/opencanary
# Read more: www.toce.ch and www.willigetpwned.com

# Set the directory to be monitored
watch_dir="$HOME/samba"

# Set the destination directory
dest_dir="$HOME/malware"

# Set the log file
log_file="$HOME/logs/folder-watcher.log"

# Set the Slack webhook URL
slack_webhook_url="https://slackhook"

# Set the Splunk HTTP Event Collector (HEC) endpoint
splunk_hec_url="https://splunkhook"

# Set the VirusTotal API key
APIKEY="getyourkeyfromvirustotal"

# Set the hash variable (comma-separated)
expected_hashes="3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"

# Set the OpenCanary name
OC_Name="Your_OC_Name"

while true; do
    file=$(inotifywait -e close_write --format "%w%f" "$watch_dir")
    echo "File $file has been closed for writing"
    
    filename=$(basename "$file")
    timestamp=$(date +"%Y%m%d%H%M%S")  # Generate a timestamp in the format - YYYYMMDDHHMMSS
    dest_file="$dest_dir/${filename%.*}-$timestamp.${filename##*.}"

    # Check if the file is still open
    while lsof "$file" >/dev/null; do
        sleep 1
    done

    # File is closed, proceed with copying
    cp "$file" "$dest_file"

    # Check if the copy was successful before proceeding
    if [ $? -eq 0 ]; then
        echo "$(date) - Successfully copied $file to $dest_file" >> "$log_file"

        # Use vt-scan.sh to submit the file to VT
        $HOME/scripts/vt-scan.sh -k "$APIKEY" -f "$dest_file" >> "$log_file"

        # Count the number of files in the malware folder
        file_count=$(find "$dest_dir" -type f | wc -l)

        # Calculate SHA256 hash for each file and count unique hash values
        hash_count=$(find "$dest_dir" -type f -exec sha256sum {} \; | awk '{print $1}' | sort -u | wc -l)

        # Check if the hash matches the expected hashes
        check_hash=$(sha256sum "$file" | awk '{print $1}')
        if [[ ! $expected_hashes =~ $check_hash ]]; then
            # Run clamscan on the copied file
            # clamscan --remove=yes "$file" >> "$log_file"

            # Simulate Antivirus the cheap way in compute terms and simply delete the file
            # With a condition to only delete files with matching hashes
            if [[ $expected_hashes =~ $check_hash ]]; then
                echo "Delete $file like an Antivirus would" >> "$log_file"
                rm "$file" >> "$log_file"
            else
                echo "Hash does not match expected hashes. Not deleting the file." >> "$log_file"
                # Notify Slack with the filename, count, and unique hash count
                curl -H 'Content-Type: application/json' -d "{\"text\":\"[$OC_Name] $(date): Malware - $filename (Files: $file_count, Unique Hashes: $hash_count)\"}" "$slack_webhook_url"
            fi
        else
            echo "Hash matches. Not triggering Slack webhook but deleting the file." >> "$log_file"
        fi

        # Notify Splunk with the filename, and unique hash count
        splunk_data=$(printf '{"OC":"%s","filename":"%s","SHA256Hash":"%s"}' "$OC_Name" "$filename" "$(sha256sum "$file" | awk '{print $1}')")
        
        splunk_result=$(curl -ksS -m 5 -H "Content-Type: application/json" -d "{\"event\":$splunk_data}" "$splunk_hec_url" 2>&1)
        http_status_code=$(echo "$splunk_result" | tail -n 1)

        if [ "$http_status_code" = "200" ] && [[ "$splunk_result" != *"\"success\": true"* ]]; then
            echo "$(date) - Successfully sent data to Splunk" >> "$log_file"
        elif [ "$http_status_code" = "200" ]; then
            echo "$(date) - Splunk response indicates success, but unexpected format: $splunk_result" >> "$log_file"
        else
            echo "$(date) - Error sending data to Splunk. HTTP Status Code: $http_status_code" >> "$log_file"
            echo "Error Details: $splunk_result" >> "$log_file"
        fi

    else
        echo "$(date) - Error copying $file to $dest_file" >> "$log_file"
    fi
done
