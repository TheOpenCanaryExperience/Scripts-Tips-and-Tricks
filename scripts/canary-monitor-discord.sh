#!/bin/bash

# Source: https://github.com/TheOpenCanaryExperience/Scripts-Tips-and-Tricks
# Credit: Scripts created from instructions to ChatGPT (why not?!)
# Based on: https://github.com/thinkst/opencanary
# Read more: www.toce.ch and www.willigetpwned.com

# Set your custom webhook URL
DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"

# Function to send webhook to Discord
send_discord_webhook() {
    curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "content=$1" \
        "$DISCORD_WEBHOOK"
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
send_discord_webhook "[OC/Loc] OpenCanary Rebooted (Service Started)"

# Infinite loop to monitor processes
while true; do
    # Check if processes disappear
    if ! is_process_running "opencanaryd.pid" || ! is_process_running "twistd"; then
        send_discord_webhook "[OC/Loc] Canary Down, Restarting Service"

        # Restart opencanary.service
        sudo systemctl restart opencanary.service

        # Wait for 5 minutes, if you're testing, don't take the service down otherwise host will reboot
        sleep 300

        # Check if the service starts successfully
        if is_service_running; then
            send_discord_webhook "[OC/Loc] Canary Up, Service Restarted"
        else
            send_discord_webhook "[OC/Loc] Canary Needs Rebooting"
            sudo reboot
        fi
    fi

    # Sleep for user-defined interval (in seconds)
    sleep 60
done
