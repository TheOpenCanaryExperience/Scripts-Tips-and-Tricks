#!/bin/bash

# Source: https://github.com/TheOpenCanaryExperience/Scripts-Tips-and-Tricks
# Credit: Scripts created from instructions to ChatGPT (why not?!)
# Based on: https://github.com/thinkst/opencanary
# Read more: www.toce.ch and www.willigetpwned.com

# Set the path to your log file
LOG_FILE="/var/log/samba-audit.log"

# Set the webhook URL
WEBHOOK_URL="https://your.webhook.url"

# Get today's month and day
TODAY_MONTH_DAY=$(date +"%b %d")

# Count the number of lines for today
LOG_COUNT=$(grep "$TODAY_MONTH_DAY" "$LOG_FILE" | grep "smbd_audit:" | wc -l)

# Check if there are no logs for TODAY_MONTH_DAY and modify the message accordingly
if [ "$LOG_COUNT" -eq 0 ]; then
    MESSAGE="[OC/Loc] Samba Access Summary\n$TODAY_MONTH_DAY: Logs appear empty"
else
    # Process each log entry and create the summary
    SUMMARY=""
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F'smbd_audit: |\\|' '{print $2}')
        # Replace empty usernames with "<blank>"
        [ -z "$username" ] && username="<blank>"
        ip_address=$(echo "$line" | awk -F'|' '{print $2}')
        computer_name=$(echo "$line" | awk -F'|' '{print $4}')
        SUMMARY="${SUMMARY}${username};${ip_address};${computer_name}\n"
    done <<< "$LOG_ENTRIES"

    # Output the final summary (unique list without repetition)
    FINAL_SUMMARY=$(echo -e "$SUMMARY" | sort -u)
    MESSAGE="[OC/Loc] Samba Access Summary\n$FINAL_SUMMARY"
fi

# Send the webhook message
curl -X POST -H "Content-Type: application/json" -d "{\"text\":\"$MESSAGE\"}" "$WEBHOOK_URL"
