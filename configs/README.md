# SMB.conf (/etc/samba/smb.conf)
Important: make sure it works, get the logging right

full_audit:success = connect open create_file pread_recv pread_send
This will give /var/log/samba-audit.log a good amount of content

Important: setting read only to no will mean it's possible to write to the folder
Canary Tokens:  Turn off the folder monitor and put some Canary Tokens into your share.  Will you get bites?
                Also chown root:root the files so the files cannot be changed (chmod 644 to keep them world-readable)

# opencanary.conf
Important: SMB log file (/var/log/samba-audit.log)
Interesting: Broadcast opencanary on many ports, censys.io picks up your OC instances :)
