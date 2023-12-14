#!/bin/bash

# Source: https://github.com/TheOpenCanaryExperience/Scripts-Tips-and-Tricks
# Credit: Scripts created from instructions to ChatGPT (why not?!)
# Based on: https://github.com/thinkst/opencanary
# Read more: www.toce.ch and www.willigetpwned.com

# Set the process names to monitor
PROCESS1="opencanaryd.pid"
PROCESS2="twistd"
WEBHOOK_URL="https://hooks.slack.com/yoursecret"

# Set the time interval for monitoring in seconds
MONITOR_INTERVAL=300  # 5 minutes
MAX_CONSECUTIVE_ALERTS=3  # Adjust this based on your preference

# Log file path
LOG_FILE="$HOME/logs/process_monitor.log"

# Flag to track if notification has been sent
notification_sent=false

# Function to check if a process is running
check_process() {
    local process_name=$1
    ps aux | grep -v grep | grep "$process_name" > /dev/null
}

# Function to send a webhook notification
send_webhook() {
    local message="[OC/LOC] Canary fell off perch"
    curl -X POST -H "Content-Type: application/json" -d "{\"text\":\"$message\"}" "$WEBHOOK_URL"
    echo "$(date): Webhook sent" >> "$LOG_FILE"
}

# Main loop
while true; do
    # Check if both processes are running
    if ! check_process "$PROCESS1" || ! check_process "$PROCESS2"; then
        # One or more processes are not running
        if [ "$notification_sent" = false ]; then
            # Log the alert to the file
            echo "$(date): Alert - Processes not running" >> "$LOG_FILE"

            # Send webhook notification
            send_webhook

            # Set the flag to true to indicate notification sent
            notification_sent=true
        fi
    else
        # Processes are running, reset the flag
        notification_sent=false
    fi
