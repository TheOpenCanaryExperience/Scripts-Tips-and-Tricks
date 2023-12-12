#!/bin/bash

# Set the directory to be monitored
watch_dir="$HOME/samba"

# Set the destination directory
dest_dir="$HOME/malware"

# Set the log file
log_file="$HOME/logs/folder-watcher.log"

# Set the Slack webhook URL
slack_webhook_url="https://hooks.slack.com/yoursecrethere"

# Set the VirusTotal API key
APIKEY="getyourapikeyfromvirustotal"

# Set the hash variable (comma-separated) - note that 3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71 will be seen a lot if you run SMB on the Internet.  You can avoid Slack or other webhooks if you ignore this.
expected_hashes="3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"

# Wait for a file or directory to be added/modified in the watched directory
inotifywait -m -r -e close_write --format "%w%f" "$watch_dir" | while read file; do
    echo "File $file has been closed for writing"
    filename=$(basename "$file")  # Extract only the filename
    timestamp=$(date +"%y%m%d%H%M%S")  # Generate a timestamp in the format -yymmddhhmmss
    dest_file="$dest_dir/${filename%.*}-$timestamp.${filename##*.}"  # Set the destination filename with timestamp

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
        /home/ubuntu/scripts/vt-scan.sh -k "$APIKEY" -f "$dest_file" >> "$log_file"

        # Count the number of files in the malware folder
        file_count=$(find "$dest_dir" -type f | wc -l)

        # Calculate SHA256 hash for each file and count unique hash values
        hash_count=$(find "$dest_dir" -type f -exec sha256sum {} \; | awk '{print $1}' | sort -u | wc -l)

        # Check if the hash matches the expected hashes
        check_hash=$(sha256sum "$file" | awk '{print $1}')
        if [[ ! $expected_hashes =~ $check_hash ]]; then
            # Run clamscan on the copied file
            # clamscan does not play well with free micro-cpu hosts in Oracle and Google Cloud!!!
            # clamscan --remove=yes "$file" >> "$log_file"

            # Simulate Antivirus the cheap way in compute terms and simply delete the file
            # With a condition to only delete files with matching hashes
            if [[ $expected_hashes =~ $check_hash ]]; then
                echo "Delete $file like an Antivirus would" >> "$log_file"
                rm "$file" >> "$log_file"
            else
                echo "Hash does not match expected hashes. Not deleting the file." >> "$log_file"
            fi

            # Notify Slack with the filename, count, and unique hash count
            curl -H 'Content-Type: application/json' -d '{"text":"'"[OC_Name/LOC] $(date): Malware - $filename (Files: $file_count, Unique Hashes: $hash_count)"'"}' "$slack_webhook_url"
        else
            echo "Hash matches. Not triggering Slack webhook but deleting the file." >> "$log_file"
        fi
    else
        echo "$(date) - Error copying $file to $dest_file" >> "$log_file"
    fi
done
