#!/bin/bash

# Source: https://github.com/TheOpenCanaryExperience/Scripts-Tips-and-Tricks
# Credit: Scripts created from instructions to ChatGPT (why not?!)
# Based on: https://github.com/thinkst/opencanary
# Read more: www.toce.ch and www.willigetpwned.com

# Set your webhook (JSON version)
JSON_WEBHOOK="https://your-webhook-url"

# Function to send webhook
send_webhook() {
    curl -X POST -H "Content-Type: application/json" -d '{"text":"'"$1"'"}' "$2"
}

# Function to check if a process is running
is_process_running() {
    pgrep -f "$1" > /dev/null
}

# Function to check if the service starts successfully
is_service_running() {
    sudo systemctl is-active --quiet opencanary.service
}

# Send webhook on script start
send_webhook "[OC/Loc] OpenCanary Rebooted (Service Started)" "$JSON_WEBHOOK"

# Infinite loop to monitor processes
while true; do
    # Check if processes disappear
    if ! is_process_running "opencanaryd.pid" || ! is_process_running "twistd"; then
        send_webhook "[OC/Loc] Canary Down, Restarting Service" "$JSON_WEBHOOK"

        # Restart opencanary.service
        sudo systemctl restart opencanary.service

        # Wait for 5 minutes, if you're testing, don't take the service down otherwise host will reboot
        sleep 300

        # Check if the service starts successfully
        if is_service_running; then
            send_webhook "[OC/Loc] Canary Up, Service Restarted" "$JSON_WEBHOOK"
        else
            send_webhook "[OC/Loc] Canary Needs Rebooting" "$JSON_WEBHOOK"
            sudo reboot
        fi
    fi

    # Sleep for user-defined interval (in seconds)
    sleep 60
done
