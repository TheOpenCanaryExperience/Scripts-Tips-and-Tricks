#!/bin/bash

log_file="/var/log/samba-audit.log"
summary_log="$HOME/logs/samba-daily-summary.log"
mastodon_instance="your_mastodon_instance"  # Replace with your Mastodon instance URL
access_token="your_access_token"  # Replace with your Mastodon access token
image_path="/path/to/your/image.png"  # Replace with the path to your image
malware_directory="$HOME/malware"  # Replace with your malware directory path

# Get yesterday's date in the format "Dec 20"
TODAY_MONTH_DAY=$(date -d "yesterday" +"%b %d")
YESTERDAY_DATE=$(date -d "yesterday" +"%Y%m%d")

# Function to upload an image and get the media ID
upload_image() {
    local image_path="$1"
    local upload_response

    upload_response=$(curl -X POST -H "Authorization: Bearer $access_token" -F "file=@$image_path" "$mastodon_instance/api/v1/media")

    # Extract media ID from the upload response
    media_id=$(echo "$upload_response" | jq -r '.id')

    echo "$media_id"
}

# Function to mask the last octet of an IP address
mask_last_octet() {
    local ip_address="$1"
    echo "$(echo "$ip_address" | awk -F'.' '{OFS="."; $NF="xxx"; print $0}')"
}

# Function to extract information from a log line
extract_info() {
    local line="$1"
    local username ip_address computer_name

    # Extract information using awk
    username=$(echo "$line" | awk -F' ' '{split($0,a,"smbd_audit: "); split(a[2],b,"|"); print b[1]}')
    ip_address=$(echo "$line" | awk -F'|' '{print $2}')
    masked_ip=$(mask_last_octet "$ip_address")
    computer_name=$(echo "$line" | awk -F'|' '{print $4}')

    # Log debug information to the summary log
    echo "Debug: Search string: $line" >> "$summary_log"
    echo "Debug: Line starting with search string: $line" >> "$summary_log"

    # Update dictionaries
    [[ -n $username ]] && ((usernames["$username"]++))
    [[ -n $masked_ip ]] && ((ip_addresses["$masked_ip"]++))
    [[ -n $computer_name ]] && ((computers["$computer_name"]++))
}

# Function to count files in the malware directory with yesterday's datestamp
count_malware_files() {
    local count=$(find "$malware_directory" -type f -name "*$YESTERDAY_DATE*" | wc -l)
    echo "$count"
}

# Initialize arrays to store unique values
declare -A usernames
declare -A ip_addresses
declare -A computers

# Read the log file line by line
while IFS= read -r line; do
    # Check if the line matches yesterday's date format
    if [[ $line =~ ^$TODAY_MONTH_DAY ]]; then
        extract_info "$line"
    fi
done < "$log_file"

# Upload the image and get the media ID
media_id=$(upload_image "$image_path")

# Count files in the malware directory with yesterday's datestamp
malware_count=$(count_malware_files)

# Construct the payload for the Mastodon API with the media ID and malware count
message="[OCX/Loc] #opencanary Samba Access Summary for $TODAY_MONTH_DAY%0A%0A"
message+="This OpenCanary received $malware_count file samples yesterday%0A%0A"
message+="List of Usernames:%0A"
for username in "${!usernames[@]}"; do
    occurrences="${usernames[$username]}"
    message+="    $username: $occurrences occurrences%0A"
done

message+="%0AList of IP Addresses:%0A"
for masked_ip in "${!ip_addresses[@]}"; do
    occurrences="${ip_addresses[$masked_ip]}"
    message+="    $masked_ip: $occurrences occurrences%0A"
done

message+="%0AList of Computers:%0A"
for computer_name in "${!computers[@]}"; do
    occurrences="${computers[$computer_name]}"
    message+="    $computer_name: $occurrences occurrences%0A"
done

# Send the payload to the Mastodon API with the media ID
curl -X POST -H "Authorization: Bearer $access_token" -d "status=$message&media_ids[]=$media_id" "$mastodon_instance/api/v1/statuses"