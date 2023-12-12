# oc-monitor.sh
A simple monitor script for Thinkst's OpenCanary

# Background
The OpenCanary offered by Thinkst on Github can occasionally stop working.  The following script is designed to listen periodically to telnet (without trying to login therefore avoiding log entries) and if telnet does not respond, it will try to restart the service and finally reboot the host.

The script is based around the instruction set here on Github for OpenCanary; it assumes you created a service on your host to run the honeypot at boot.
The script should count how many times it tried to restart the service before rebooting.  It runs best in root's crontab.
NB: If you take down your OpenCanary for maintenance, beware that it may reboot randomly unless you stop it... :D

There are some variables to check based on your environment:

# Set the path to the counter file
COUNTER_FILE="/path/to/counter.txt"
Ensure you can read, write and create in this folder.  The count will be reset upon success.

# Your service name
SERVICE_NAME="your_service_name"
Amend this to match your service.

# Log file path
LOG_FILE="/path/to/watcher.log"
Again, r/w location necessary; also consider log rotation.

# Slack webhook URL
SLACK_WEBHOOK_URL="your_slack_webhook_url"
You can modify the script to webhook into anything you want.  I like Slack.
