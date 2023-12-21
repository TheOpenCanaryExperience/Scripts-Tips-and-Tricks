import json
from collections import Counter
from datetime import datetime, timedelta
from mastodon import Mastodon

def map_dst_port(dst_port):
    port_mapping = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        69: 'TFTP',
        80: 'HTTP',
        123: 'NTP',
        445: 'SMB',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        8080: 'PROXY',
        5060: 'SIP',
        5901: 'VNC',
        6379: 'REDIS',
        9418: 'GIT'
    }
    return port_mapping.get(dst_port, str(dst_port))

def process_opencanary_log(log_file_path):
    usernames = Counter()
    passwords = Counter()
    dst_ports = Counter()
    attacker_ips = Counter()
    total_connections = 0  # Initialize the count for total connections

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            log_entry = json.loads(line)

            # Process each log entry
            dst_port = log_entry.get('dst_port', None)

            # Ignore log entries with dst_port -1
            if dst_port is not None and dst_port != -1:
                dst_ports[map_dst_port(dst_port)] += 1
                total_connections += 1  # Increment the total connections count

                username = log_entry['logdata'].get('USERNAME', None)
                if username:
                    usernames[username] += 1

                password = log_entry['logdata'].get('PASSWORD', None)
                if password:
                    passwords[password] += 1

                src_host = log_entry.get('src_host', None)
                if src_host:
                    attacker_ips[src_host.rsplit('.', 1)[0] + '.xxx'] += 1

    # Prepare the results
    result_str = f"[OC/Loc] #opencanary analysis for yesterday\n\n"

    # Port Popularity with Connection Count
    result_str += "Port Popularity (Port/Count):\n"
    for port, count in dst_ports.most_common():
        result_str += f"  {port}: {count}\n"
    result_str += f"\nTotal Connection Attempts: {total_connections}\n"

    # Usernames
    result_str += f"\nTotal Unique Usernames Seen: {len(usernames)}\n"
    if usernames:
        result_str += "Top 10 Usernames (Username/Count):\n"
        for username, count in usernames.most_common(10):
            result_str += f"  {username}: {count}\n"

    # Passwords
    result_str += f"\nTotal Distinct Passwords: {len(passwords)}\n"
    if passwords:
        result_str += "Top 10 Passwords (Password/Count):\n"
        for password, count in passwords.most_common(10):
            result_str += f"  {password}: {count}\n"

    # Attacker IPs
    result_str += f"\nTotal Unique Attacker IPs: {len(attacker_ips)}\n"
    if attacker_ips:
        result_str += "Top 10 IPs Seen:\n"
        for ip, count in attacker_ips.most_common(10):
            result_str += f"  {ip}: {count}\n"

    # Create Mastodon API instance
    mastodon_instance_url = 'your_instance_url'
    mastodon_access_token = 'your_access_token'

    # Post the result to Mastodon with an image
    mastodon = Mastodon(
        api_base_url=mastodon_instance_url,
        access_token=mastodon_access_token
    )

    # Upload an image 
    media_id = mastodon.media_post('/home/opencanary/image/daily.jpg', description='Opencanary Image')['id']

    # Pump results into Mastodon string with the uploaded image
    result_str_mastodon = result_str

    # Post the status with the media_id
    mastodon.status_post(result_str_mastodon, media_ids=[media_id])

if __name__ == "__main__":
    # Provide the complete path to the log file, YOU NEED TO CHANGE THIS. Script is running on assumption you rotate daily
    log_file_path = '/home/opencanary/logs/opencanary.log.1'

    # Process opencanary log and post the result to Mastodon
    process_opencanary_log(log_file_path)
