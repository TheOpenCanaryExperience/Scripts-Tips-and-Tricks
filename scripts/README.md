# Folder-Watcher.sh
## Trigger: On boot, either a service running or crontab #reboot
This will monitor the Samba folder and when files have copied, move to malware, delete (command line, like an antivirus - clamav may kill your microhost) and will fire a webhook if the hash is not the common file hash.

### Default behaviour is to only delete the following file and only notify Slack/webhook on other files
3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71 (https://www.virustotal.com/gui/file/3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71) is the main file I have seen in my OpenCanary SMB shares.

### Webhook into Splunk
It will also push a webhook into Splunk so that you can report in a dashboard what you see.  It's currently configured to deliver the following in the Splunk webhook: OC_Name, SHA256sum (on dest_file since deletion can happen in the script) and the filename itself.

# canary-monitor.sh
## Trigger: Cron @reboot
Watches opencanaryd and twistd in ps -ef, sends webhook when they go AWOL, tries to start the service (passwordless sudo needed) and if all fails, reboots (hits it with a hammer)

# monthly-malware-mover.sh
## Trigger: Cron, last day of the month just before midnight
<code>59 23 28-31 * * [ "$(date +\%d -d tomorrow)" == "01" ] && $HOME/scripts/monthly-malware-mover.sh</code>

Moves the malware from $HOME/malware into a monthly folder and provides a summary of the files and hashes
No longer processes samba-audit.log since this is done daily

# samba-daily-summary.sh
## Trigger: Cron, daily, 08:00 
Pulls the three-letter version of the month and adds the number for yesterday (e.g. "Dec 14); greps and awks the /var/log/samba-audit.log for username, ip_address and computer_name.  Then sends it to you via Webhook.

# malware-summary-mastodon.sh
## Trigger: Cron, every 4 hours (hours_to_check in script)
Sends a summary of the files to Mastodon with links to VirusTotal

# samba-daily-summary-mastodon.sh
## Trigger: Cron, daily
Sends a summary of files (volume) submitted with unique hashes (hyperlink into VirusTotal), unique usernames, IP addresses (final octet xxx) and computernames seen
And am image

# oc-daily-summary-mastodon.py
## Trigger: Cron, daily
Sends a summary of what the opencanary has seen to Mastodon
Ports - top 10 and total count
Usernames - top 10 and total unique count
Passwords - top 10 and total unique count
Source IPs - top ten (final octet xxx) plus unique count
And an image

# daily-extract-systemname.py
##Trigger: Cron, daily
Designed to run on the yesterday opencanary.log (I scp these to a host for this) and gets the following into new files:
Ports (named nicely)
Usernames
Passwords
VNC Passwords
Source IPs

# daily-extract-param.py
## Run manually, pass system parameter and days backward to process
