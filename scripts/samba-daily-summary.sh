#!/bin/bash

# Source: https://github.com/TheOpenCanaryExperience/Scripts-Tips-and-Tricks
# Credit: Scripts created from instructions to ChatGPT (why not?!)
# Based on: https://github.com/thinkst/opencanary
# Read more: www.toce.ch and www.willigetpwned.com

log_file="/var/log/samba-audit.log"
summary_log="$HOME/logs/samba-daily-summary.log"
webhook_url="YOUR_WEBHOOK_URL"

# Get yesterday's date in the format "Dec 14"
TODAY_MONTH_DAY=$(date -d "yesterday" +"%b %d")

# Function to extract information from a log line
extract_info() {
    local line="$1"
    local username ip_address computer_name

    # Extract information using awk
    username=$(echo "$line" | awk -F' ' '{split($0,a,"smbd_audit: "); split(a[2],b,"|"); print b[1]}')
    ip_address=$(echo "$line" | awk -F'|' '{print $2}')
    computer_name=$(echo "$line" | awk -F'|' '{print $4}')

    # Log debug information to the summary log
    echo "Debug: Search string: $line" >> "$summary_log"
    echo "Debug: Line starting with search string: $line" >> "$summary_log"

    # Update dictionaries
    [[ -n $username ]] && ((usernames["$username"]++))
    [[ -n $ip_address ]] && ((ip_addresses["$ip_address"]++))
    [[ -n $computer_name ]] && ((computers["$computer_name"]++))
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

# Construct the payload for the webhook
payload="{\"text\":\"[OC/Loc] Samba Access Summary for $TODAY_MONTH_DAY\n\nList of Usernames:\n"
for username in "${!usernames[@]}"; do
    payload+=" $username: ${usernames[$username]} occurrences\n"
done

payload+="\nList of IP Addresses:\n"
for ip_address in "${!ip_addresses[@]}"; do
    payload+=" $ip_address: ${ip_addresses[$ip_address]} occurrences\n"
done

payload+="\nList of Computers:\n"
for computer_name in "${!computers[@]}"; do
    payload+=" $computer_name: ${computers[$computer_name]} occurrences\n"
done

payload+="\"}"

# Send the payload to the webhook
curl -X POST -H "Content-Type: application/json" -d "$payload" "$webhook_url"
