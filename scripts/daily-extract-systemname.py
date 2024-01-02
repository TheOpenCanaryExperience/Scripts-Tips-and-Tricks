#!/usr/bin/env python3

import os
import json
import datetime

# Function to map port numbers
def map_port(port):
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
    return port_mapping.get(port, str(port))

# Function to extract and write content to files
def extract_content(log_file, system_name):
    date_yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y%m%d')
    filtered_folder = os.path.join(os.environ['HOME'], 'logs', 'reporting', system_name, 'filtered')
    os.makedirs(filtered_folder, exist_ok=True)

    port_filename = f'port_{system_name}_{date_yesterday}.log'
    username_filename = f'username_{system_name}_{date_yesterday}.log'
    password_filename = f'password_{system_name}_{date_yesterday}.log'
    vncpass_filename = f'vncpass_{system_name}_{date_yesterday}.log'

    with open(log_file, 'r') as f:
        for line in f:
            log_data = json.loads(line.strip())

            # Extract and write port information
            dst_port = log_data.get('dst_port', None)
            if dst_port is not None:
                translated_port = map_port(dst_port)
                with open(os.path.join(filtered_folder, port_filename), 'a') as port_file:
                    port_file.write(f'{translated_port}\n')

            # Extract and write USERNAME information
            username = log_data.get('logdata', {}).get('USERNAME', None)
            if username is not None and username != "":
                with open(os.path.join(filtered_folder, username_filename), 'a') as username_file:
                    username_file.write(f'{username}\n')
            else:
                with open(os.path.join(filtered_folder, username_filename), 'a') as username_file:
                    username_file.write('<blank>\n')

            # Extract and write PASSWORD information
            password = log_data.get('logdata', {}).get('PASSWORD', None)
            if password is not None and password != "":
                with open(os.path.join(filtered_folder, password_filename), 'a') as password_file:
                    password_file.write(f'{password}\n')
            else:
                with open(os.path.join(filtered_folder, password_filename), 'a') as password_file:
                    password_file.write('<blank>\n')

            # Extract and write VNC Password information
            vnc_password = log_data.get('logdata', {}).get('VNC Password', None)
            if vnc_password is not None and vnc_password != "":
                with open(os.path.join(filtered_folder, vncpass_filename), 'a') as vncpass_file:
                    vncpass_file.write(f'{vnc_password}\n')
            else:
                with open(os.path.join(filtered_folder, vncpass_filename), 'a') as vncpass_file:
                    vncpass_file.write('<blank>\n')

if __name__ == '__main__':
    system_name = "yourshere"  # Replace with the actual system name
    log_folder = os.path.join(os.environ['HOME'], 'logs', 'reporting', system_name)

    # Get yesterday's date
    date_yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y%m%d')

    # Build the log filename for yesterday
    log_filename = f'opencanary.log_{date_yesterday}'

    # Full path to the log file
    log_file_path = os.path.join(log_folder, log_filename)

    # Call the function to extract content
    extract_content(log_file_path, system_name)
