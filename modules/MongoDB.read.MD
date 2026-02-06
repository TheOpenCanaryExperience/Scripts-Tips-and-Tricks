# MongoDB Honeypot Module Installation Guide for OpenCanary

## Overview
This guide walks you through adding a fully functional MongoDB honeypot to a clean OpenCanary installation. The module implements the MongoDB wire protocol and captures connection attempts, commands, and authentication attempts from attackers.

## What Gets Logged
- **Connections**: Every connection to port 27017 with source/destination IPs
- **Commands**: All MongoDB commands (isMaster, listDatabases, queries, etc.)
- **Authentication Attempts**: Usernames, auth mechanisms (SCRAM-SHA-1, SCRAM-SHA-256), and full auth payloads
- **Disconnections**: When attackers close the connection

## Prerequisites
- Fresh OpenCanary installation (see https://docs.opencanary.org for installation)
- Root/sudo access to the server
- Python 3.x (typically installed with OpenCanary)
- Basic familiarity with command line and text editing

## Files Required

You'll need these three files:
1. **mongodb.py** - The honeypot module
2. **mongodb_config.conf** - Configuration snippet (for reference)
3. **MONGODB_INSTALLATION_GUIDE.md** - This guide

Download or have these files ready before starting.

## Installation Steps

### Step 1: Locate Your OpenCanary Installation

First, find where OpenCanary is installed on your system:

```bash
python3 -c "import opencanary.modules; import os; print(os.path.dirname(opencanary.modules.__file__))"
```

This will output a path like:
- `/usr/local/lib/python3.12/dist-packages/opencanary/modules` (system-wide installation)
- `/home/opencanary/env/lib/python3.12/site-packages/opencanary/modules` (virtualenv installation)
- `/opt/opencanary/lib/python3.x/site-packages/opencanary/modules` (custom installation)

**Important:** Save this path - you'll need it multiple times. For the rest of this guide, we'll use `/path/to/opencanary/modules` as a placeholder. **Replace it with your actual path.**

To make things easier, set an environment variable:

```bash
export OC_MODULES=$(python3 -c "import opencanary.modules; import os; print(os.path.dirname(opencanary.modules.__file__))")
echo $OC_MODULES
```

Now you can use `$OC_MODULES` instead of typing the full path each time.

### Step 2: Add MongoDB Logtype to Logger

Every OpenCanary module needs a logtype constant. We'll add one for MongoDB.

**Find your logger.py location:**

```bash
python3 -c "import opencanary.logger; import os; print(os.path.dirname(opencanary.logger.__file__))"
```

**Edit logger.py:**

```bash
nano $(python3 -c "import opencanary.logger; import os; print(os.path.join(os.path.dirname(opencanary.logger.__file__), 'logger.py'))")
```

**Find this section** (search for LOG_LLMNR or scroll down to around line 130-150):

```python
    LOG_LLMNR_QUERY_RESPONSE = 19001
    LOG_USER_0 = 99000
    LOG_USER_1 = 99001
```

**Add the MongoDB logtype** between LOG_LLMNR_QUERY_RESPONSE and LOG_USER_0:

```python
    LOG_LLMNR_QUERY_RESPONSE = 19001
    LOG_MONGODB_LOGIN_ATTEMPT = 20001
    LOG_USER_0 = 99000
    LOG_USER_1 = 99001
```

**Save and exit:**
- In nano: Press `Ctrl+X`, then `Y`, then `Enter`
- In vim: Press `Esc`, type `:wq`, press `Enter`

### Step 3: Copy the MongoDB Module

Copy the `mongodb.py` file to your OpenCanary modules directory.

**If the file is in your current directory:**

```bash
sudo cp mongodb.py $OC_MODULES/
```

**If you need to download it first:**

```bash
# Download to current directory first, then:
sudo cp mongodb.py $OC_MODULES/
```

**Set proper ownership** (adjust user:group to match your OpenCanary installation):

```bash
# For system installation:
sudo chown root:root $OC_MODULES/mongodb.py

# For virtualenv installation (if OpenCanary runs as 'opencanary' user):
sudo chown opencanary:opencanary $OC_MODULES/mongodb.py
```

**Verify the file is there:**

```bash
ls -la $OC_MODULES/mongodb.py
```

You should see output like:
```
-rw-r--r-- 1 root root 15004 Feb  5 19:08 /path/to/opencanary/modules/mongodb.py
```

### Step 4: Register MongoDB in opencanary.tac

OpenCanary uses a Twisted Application Configuration file (.tac) that lists all modules to load. We need to add MongoDB to this file.

**Find the opencanary.tac file:**

```bash
which opencanaryd
```

This shows where the opencanaryd executable is (e.g., `/usr/local/bin/opencanaryd` or `/home/opencanary/env/bin/opencanaryd`).

The .tac file is typically in the same directory or in a `bin` subdirectory.

**Common locations:**
- `/usr/local/bin/opencanary.tac`
- `/home/opencanary/env/bin/opencanary.tac`
- `/opt/opencanary/bin/opencanary.tac`

**Find it automatically:**

```bash
find $(dirname $(which opencanaryd)) -name "opencanary.tac"
```

**Edit the file:**

```bash
nano $(find $(dirname $(which opencanaryd)) -name "opencanary.tac")
```

**Step 4a: Add the import**

Find the import section at the top of the file (around lines 8-20). You'll see imports like:

```python
from opencanary.modules.http import CanaryHTTP
from opencanary.modules.https import CanaryHTTPS
from opencanary.modules.ftp import CanaryFTP
from opencanary.modules.ssh import CanarySSH
from opencanary.modules.telnet import Telnet
from opencanary.modules.httpproxy import HTTPProxy
from opencanary.modules.mysql import CanaryMySQL
from opencanary.modules.mssql import MSSQL
from opencanary.modules.ntp import CanaryNtp
from opencanary.modules.tftp import CanaryTftp
from opencanary.modules.vnc import CanaryVNC
from opencanary.modules.sip import CanarySIP
from opencanary.modules.git import CanaryGit
from opencanary.modules.redis import CanaryRedis
from opencanary.modules.tcpbanner import CanaryTCPBanner
from opencanary.modules.rdp import CanaryRDP
```

**Add this line anywhere in that group:**

```python
from opencanary.modules.mongodb import CanaryMongoDB
```

**Step 4b: Add to MODULES list**

Scroll down to find the MODULES list (around line 35-55):

```python
MODULES = [
    CanaryFTP,
    CanaryGit,
    CanaryHTTP,
    CanaryHTTPS,
    CanaryMySQL,
    CanaryNtp,
    CanaryRDP,
    CanaryRedis,
    CanarySIP,
    CanarySSH,
    CanaryTCPBanner,
    CanaryTftp,
    CanaryVNC,
    HTTPProxy,
    MSSQL,
    Telnet,
    # CanaryExample0,
    # CanaryExample1,
]
```

**Add `CanaryMongoDB,` to the list** (alphabetical order recommended but not required):

```python
MODULES = [
    CanaryFTP,
    CanaryGit,
    CanaryHTTP,
    CanaryHTTPS,
    CanaryMongoDB,    # <-- ADD THIS LINE
    CanaryMySQL,
    CanaryNtp,
    CanaryRDP,
    CanaryRedis,
    CanarySIP,
    CanarySSH,
    CanaryTCPBanner,
    CanaryTftp,
    CanaryVNC,
    HTTPProxy,
    MSSQL,
    Telnet,
]
```

**Save and exit** (Ctrl+X, Y, Enter in nano).

### Step 5: Configure MongoDB in opencanary.conf

Now we need to enable and configure the MongoDB module in OpenCanary's configuration file.

**Locate the config file:**

Common locations:
- `/etc/opencanaryd/opencanary.conf`
- `~/.opencanary.conf`
- `/opt/opencanary/opencanary.conf`

**Find it automatically:**

```bash
# Check if it's in /etc
ls /etc/opencanaryd/opencanary.conf

# Or check default location
ls ~/.opencanary.conf
```

**Edit the configuration:**

```bash
sudo nano /etc/opencanaryd/opencanary.conf
```

**Understanding the JSON structure:**

OpenCanary config is a JSON file. Each service has settings like:
```json
{
    "device.node_id": "opencanary-1",
    
    "ftp.enabled": true,
    "ftp.port": 21,
    
    "http.enabled": true,
    "http.port": 80,
    
    "ssh.enabled": true,
    "ssh.port": 22
}
```

**Add MongoDB configuration:**

Find the last service in the config (look for the last service settings before the closing `}`). Add a comma after the last entry, then add these three lines:

```json
    "mongodb.enabled": true,
    "mongodb.port": 27017,
    "mongodb.version": "4.4.6"
```

**Complete example:**

```json
{
    "device.node_id": "opencanary-1",
    "device.listen_addr": "0.0.0.0",
    
    "ftp.enabled": true,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",
    
    "http.enabled": true,
    "http.port": 80,
    "http.banner": "Apache/2.2.22 (Ubuntu)",
    
    "ssh.enabled": true,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_5.1p1 Debian-4",
    
    "mongodb.enabled": true,
    "mongodb.port": 27017,
    "mongodb.version": "4.4.6"
}
```

**Critical JSON syntax rules:**
- Every line except the last one in a section needs a comma at the end
- The last line before a closing `}` should NOT have a comma
- Strings must be in double quotes `"`, not single quotes `'`
- Boolean values are `true` or `false` (lowercase, no quotes)

**Validate your JSON syntax:**

```bash
python3 -m json.tool /etc/opencanaryd/opencanary.conf > /dev/null && echo "✓ JSON is valid" || echo "✗ JSON has syntax errors"
```

If you get errors, check for:
- Missing or extra commas
- Missing quotes around strings
- Mismatched brackets `{}` or `[]`

**Save and exit.**

### Step 6: Restart OpenCanary

**If using systemd:**

```bash
sudo systemctl restart opencanary
```

**If running manually:**

```bash
sudo opencanaryd --restart
```

**Check if it started successfully:**

```bash
sudo systemctl status opencanary
```

Should show "active (running)".

### Step 7: Verify MongoDB is Running

**Test 1: Check if the port is listening**

```bash
sudo netstat -tlnp | grep 27017
```

Expected output:
```
tcp        0      0 0.0.0.0:27017           0.0.0.0:*               LISTEN      12345/python
```

If you don't have `netstat`, use `ss`:

```bash
sudo ss -tlnp | grep 27017
```

**Test 2: Check startup logs**

```bash
sudo journalctl -u opencanary -n 50 | grep -i mongodb
```

You should see:
```
{"logdata": {"msg": {"logdata": "Added service from class CanaryMongoDB in opencanary.modules.mongodb to fake"}}}
```

**Test 3: Verify all services started**

```bash
sudo journalctl -u opencanary -n 100 | grep "starting on"
```

You should see MongoDB in the list:
```
[-] CanaryMongoDB starting on 27017
```

### Step 8: Test the Honeypot

**Test 1: Simple connection test**

```bash
nc localhost 27017
```

The connection should hang (waiting for input). Press `Ctrl+C` to exit.

**Test 2: Check if connection was logged**

Find your OpenCanary log file location (usually `/var/log/opencanary.log` or `~/logs/opencanary.log`):

```bash
# Common locations
tail ~/logs/opencanary.log
# or
sudo tail /var/log/opencanary.log
```

Filter for MongoDB events:

```bash
tail -20 ~/logs/opencanary.log | grep mongodb
```

You should see:
```json
{"dst_host": "127.0.0.1", "dst_port": 27017, "logdata": {"action": "mongodb.connection"}, "logtype": 20001, "src_host": "127.0.0.1", "src_port": 54321}
{"logdata": {"action": "mongodb.disconnect"}, "logtype": 20001}
```

**Test 3: Watch logs in real-time**

Open a terminal and run:

```bash
tail -f ~/logs/opencanary.log | grep --line-buffered mongodb
```

In another terminal, connect:

```bash
nc localhost 27017
# Wait 2 seconds
# Press Ctrl+C
```

You should see events appear in the first terminal immediately.

**Test 4: Full MongoDB protocol test**

Install pymongo (Python MongoDB client):

```bash
pip3 install pymongo --break-system-packages
```

Or if using a virtualenv:

```bash
source ~/env/bin/activate
pip install pymongo
```

Run a full authentication test:

```bash
python3 << 'EOF'
from pymongo import MongoClient

try:
    client = MongoClient(
        'localhost',
        27017,
        username='admin',
        password='password123',
        authSource='admin',
        serverSelectionTimeoutMS=3000
    )
    client.admin.command('ping')
except Exception as e:
    print(f"Expected auth failure: {e}")
EOF
```

Check the logs:

```bash
tail -10 ~/logs/opencanary.log | grep mongodb
```

You should now see multiple events:
1. **mongodb.connection** - Initial connection
2. **mongodb.command** - isMaster/hello query
3. **mongodb.auth_attempt** - Authentication with username "admin"
4. **mongodb.disconnect** - Connection closed

Example log output:
```json
{"logdata": {"action": "mongodb.connection"}, "logtype": 20001, "src_host": "127.0.0.1"}
{"logdata": {"action": "mongodb.command", "command": "query:admin.$cmd", "query": "{'ismaster': 1}"}, "logtype": 20001}
{"logdata": {"action": "mongodb.auth_attempt", "username": "admin", "mechanism": "SCRAM-SHA-1"}, "logtype": 20001}
{"logdata": {"action": "mongodb.disconnect"}, "logtype": 20001}
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `mongodb.enabled` | false | Enable/disable the MongoDB honeypot |
| `mongodb.port` | 27017 | Port to listen on (27017 is standard MongoDB port) |
| `mongodb.version` | "4.4.6" | MongoDB version string sent to clients |

### Recommended Version Strings

Choose a version based on what you want to attract:

- **"4.4.6"** - Stable, widely deployed (recommended)
- **"3.6.23"** - Older version, may attract attackers looking for known CVEs
- **"5.0.9"** - More recent stable version
- **"6.0.3"** - Latest features
- **"7.0.0"** - Bleeding edge

Older versions (3.x, 4.0.x) may attract more attackers looking for specific vulnerabilities.

## What Gets Logged

### Connection Events
```json
{
  "logtype": 20001,
  "action": "mongodb.connection",
  "src_host": "192.168.1.100",
  "src_port": 54321,
  "dst_host": "10.0.47.222",
  "dst_port": 27017,
  "node_id": "Switzerland"
}
```

### Authentication Attempts
```json
{
  "logtype": 20001,
  "action": "mongodb.auth_attempt",
  "src_host": "192.168.1.100",
  "src_port": 54321,
  "username": "admin",
  "mechanism": "SCRAM-SHA-1",
  "auth_data": "{'saslStart': 1, 'mechanism': 'SCRAM-SHA-1', 'payload': '...'}"
}
```

### Commands
```json
{
  "logtype": 20001,
  "action": "mongodb.command",
  "src_host": "192.168.1.100",
  "command": "listDatabases",
  "query": "{'listDatabases': 1}"
}
```

### Disconnections
```json
{
  "logtype": 20001,
  "action": "mongodb.disconnect",
  "src_host": "192.168.1.100",
  "src_port": 54321
}
```

## Troubleshooting

### Service Won't Start

**Check if port is already in use:**
```bash
sudo netstat -tlnp | grep 27017
```

If something else is using port 27017, either stop that service or configure MongoDB honeypot to use a different port.

**Check for errors:**
```bash
sudo journalctl -u opencanary -n 100 | grep -i "error\|exception\|traceback"
```

**Validate JSON config:**
```bash
python3 -m json.tool /etc/opencanaryd/opencanary.conf
```

### No Logs Appearing

**Verify mongodb.enabled is true:**
```bash
python3 -c "import json; print(json.load(open('/etc/opencanaryd/opencanary.conf'))['mongodb.enabled'])"
```

Should output: `True`

**Check logging configuration:**
Make sure your OpenCanary logging is properly configured in the config file.

**Test with verbose output:**
```bash
tail -f ~/logs/opencanary.log
# In another terminal:
nc localhost 27017
```

You should see new log entries appear.

### Module Not Loading

**Verify module file exists:**
```bash
ls -la ~/env/lib/python3.12/site-packages/opencanary/modules/mongodb.py
```

**Check it's registered in opencanary.tac:**
```bash
grep -i mongodb ~/env/bin/opencanary.tac
```

Should show the import and the module in the MODULES list.

**Check for syntax errors:**
```bash
python3 -m py_compile ~/env/lib/python3.12/site-packages/opencanary/modules/mongodb.py
```

If there are syntax errors, it will show them.

## Firewall Configuration

To expose the honeypot to the internet, open port 27017:

**UFW:**
```bash
sudo ufw allow 27017/tcp
```

**iptables:**
```bash
sudo iptables -A INPUT -p tcp --dport 27017 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

**Cloud Provider:**
If running on AWS, Azure, GCP, etc., add an inbound rule for TCP port 27017 in your security group/firewall.

## Monitoring

**Watch logs in real-time:**
```bash
tail -f ~/logs/opencanary.log | grep --line-buffered mongodb
```

**Count attacks today:**
```bash
grep mongodb ~/logs/opencanary.log | grep "$(date +%Y-%m-%d)" | wc -l
```

**Top attacking IPs:**
```bash
grep mongodb ~/logs/opencanary.log | grep -o '"src_host": "[^"]*"' | cut -d'"' -f4 | sort | uniq -c | sort -rn | head -10
```

**Authentication attempts with usernames:**
```bash
grep "mongodb.auth_attempt" ~/logs/opencanary.log | grep -o '"username": "[^"]*"' | cut -d'"' -f4 | sort | uniq -c | sort -rn
```

## Integration with SIEM

OpenCanary logs can be forwarded to your SIEM system. Configure the logger section in opencanary.conf:

**For Syslog:**
```json
"logger": {
    "class": "PyLogger",
    "kwargs": {
        "handlers": {
            "syslog": {
                "class": "logging.handlers.SysLogHandler",
                "address": ["your-siem-server", 514]
            }
        }
    }
}
```

**For File + Syslog:**
```json
"logger": {
    "class": "PyLogger",
    "kwargs": {
        "handlers": {
            "file": {
                "class": "logging.FileHandler",
                "filename": "/var/log/opencanary.log"
            },
            "syslog": {
                "class": "logging.handlers.SysLogHandler",
                "address": ["siem.example.com", 514]
            }
        }
    }
}
```

## Security Notes

1. **No Real Data**: This honeypot contains no actual MongoDB data - it only emulates protocol responses
2. **Authentication Always Fails**: All authentication attempts are logged and rejected
3. **Resource Usage**: Each connection creates a protocol handler - monitor resource usage if under heavy attack
4. **False Positives**: Legitimate network scanners (Shodan, Censys) will trigger logs
5. **Legal Considerations**: Ensure honeypot deployment complies with your organization's security policy

## Uninstalling

To remove the MongoDB honeypot:

1. **Disable in config:**
   ```bash
   nano /etc/opencanaryd/opencanary.conf
   # Change "mongodb.enabled": true to false
   ```

2. **Restart OpenCanary:**
   ```bash
   sudo systemctl restart opencanary
   ```

3. **Optional - Remove files:**
   ```bash
   rm ~/env/lib/python3.12/site-packages/opencanary/modules/mongodb.py
   # Edit ~/env/bin/opencanary.tac and remove the CanaryMongoDB import and entry
   ```

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review OpenCanary logs: `sudo journalctl -u opencanary -n 100`
3. Verify all steps were completed correctly
4. Check OpenCanary documentation: https://docs.opencanary.org

## Credits

MongoDB honeypot module for OpenCanary implementing the MongoDB wire protocol with full authentication trapping capabilities.

## Changelog

### Version 1.0 (2026-02-05)
- Initial release
- MongoDB wire protocol implementation (OP_QUERY, OP_MSG)
- BSON encoding/decoding
- Authentication attempt logging (SCRAM-SHA-1, SCRAM-SHA-256)
- Command logging
- Configurable MongoDB version string
- Full OpenCanary integration
