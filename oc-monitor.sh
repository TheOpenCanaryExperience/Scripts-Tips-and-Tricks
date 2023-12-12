#!/bin/bash

# Set the path to the counter file
COUNTER_FILE="/path/to/counter.txt"

# Your service name
SERVICE_NAME="your_service_name"

# Log file path
LOG_FILE="/path/to/watcher.log"

# Slack webhook URL
SLACK_WEBHOOK_URL="your_slack_webhook_url"

# Function to log messages
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") $1" >> "$LOG_FILE"
}

# Function to send a message to Slack
send_to_slack() {
    local message="$1"
    curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"$message\"}" "$SLACK_WEBHOOK_URL"
}

# Function to check if the script has sufficient rights
check_permissions() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root (sudo)." >&2
        exit 1
    fi
}

# Function to increment the counter
increment_counter() {
    counter=$(cat "$COUNTER_FILE" 2>/dev/null)
    if [ -z "$counter" ]; then
        counter=0
    fi
    echo $((counter + 1)) > "$COUNTER_FILE"
    log "Counter incremented to $((counter + 1))"
}

# Function to reset the counter
reset_counter() {
    echo 0 > "$COUNTER_FILE"
    log "Counter reset to 0"
}

# Function to check if telnet to localhost is possible
check_telnet() {
    (echo >/dev/tcp/localhost/23) &>/dev/null
    return $?
}

# Function to start the service using systemctl
start_service() {
    if sudo systemctl start "$SERVICE_NAME"; then
        log "Service $SERVICE_NAME started"
    else
        log "Failed to start service $SERVICE_NAME. Check permissions."
        send_to_slack "Failed to start service $SERVICE_NAME. Check permissions."
    fi
}

# Function to check the status of the service using systemctl
check_service_status() {
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        return 0
    else
        log "Service $SERVICE_NAME is not active"
        return 1
    fi
}

# Function to check if the script has necessary rights
check_permissions() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root (sudo)." >&2
        exit 1
    fi
}

# Main function
main() {
    log "Running script"

    check_permissions

    if check_telnet; then
        # Telnet is successful, reset the counter
        reset_counter
    else
        # Telnet failed
        increment_counter

        if [ $(cat "$COUNTER_FILE") -ge 3 ]; then
            # Counter is 3 or more, trigger a reboot
            log "Rebooting due to telnet failure"
            send_to_slack "Rebooting due to telnet failure"
            sudo reboot
        else
            # Counter is less than 3, try starting the service
            start_service

            # Check if starting the service resolved the issue
            if check_service_status; then
                reset_counter
                send_to_slack "Service $SERVICE_NAME restarted successfully"
            else
                # Service is not running after starting, increment counter
                increment_counter
            fi
        fi
    fi

    log "Script execution complete"
}

# Run the main function
main
