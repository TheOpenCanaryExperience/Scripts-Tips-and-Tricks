# Folder-Watcher.sh
## Trigger: On boot, either a service running or crontab #reboot
This will monitor the Samba folder and when files have copied, move to malware, delete (command line, like an antivirus - clamav may kill your microhost) and will fire a webhook if the hash is not the common file hash.

3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71 (https://www.virustotal.com/gui/file/3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71) is the main file I have seen in my OpenCanary SMB shares.

# process-monitor.sh
## Trigger: Cron, 5 minutes
Watches opencanaryd and twistd in ps -ef, sends webhook when they go AWOL.  Should wait for oc-monitor.sh to rectify

# monthly-malware-mover.sh
## Trigger: Cron, last day of the month just before midnight
<code>59 23 28-31 * * [ "$(date +\%d -d tomorrow)" == "01" ] && $HOME/scripts/monthly-malware-mover.sh</code>

Moves the malware from $HOME/malware into a monthly folder and provides a summary of the files, hashes and tries to get usernames/IPs from samba-audit.log
