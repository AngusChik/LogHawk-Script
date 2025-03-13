#!/usr/bin/env python3
import re

# Manual Configuration
log_file = "/media/sf_Shared/SharedFolder/demo.txt" # <-- This is where you change the file path.
# "C:\Users\Angus\Desktop\Shared\Shared Folder
# Thresholds
TRAFFIC_SPIKE_THRESHOLD = 100
WEB_FAILED_LOGIN_THRESHOLD = 5
SSH_FAILED_LOGIN_THRESHOLD = 5

# Initialize Counters
status_count = {"404": 0, "401": 0, "200": 0} # Track HTTP status codes (web)
ip_counter = {}                               # Count requests per IP (web)
ssh_failed_counter = {}                       # Count SSH failed logins
critical_errors = []                          # Store critical system errors
cron_jobs = []                                # Store suspicious cron activity

# Open and Process the Single Log File
with open(log_file, 'r') as logFile:
    for line in logFile:
        # SSH Log Check
        if "Failed password" in line:
            ssh_match = re.search(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', line)
            if ssh_match:
                ip = ssh_match.group(1)
                if ip in ssh_failed_counter:
                    ssh_failed_counter[ip] += 1
                else:
                    ssh_failed_counter[ip] = 1

        # Web Log Check 
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?\s(404|401|200)\s', line)
        if match:
            ip = match.group(1)
            status = match.group(2)

            # Update status code counter
            status_count[status] += 1

            # Update request counts by IP
            if ip in ip_counter:
                ip_counter[ip] += 1
            else:
                ip_counter[ip] = 1

        # Critical Errors Check
        if "ERROR" in line or "CRITICAL" in line:
            critical_errors.append(line.strip())

        # Suspicious Cron Jobs 
        if re.search(r'CRON.*CMD', line):
            cron_jobs.append(line.strip())

# REPORT SECTION
print("\nLogHawk Threat Report\n")

# 1. Too Many Failed SSH Logins
if ssh_failed_counter:
    print("SSH Failed Logins:")

    # Flag to track if we found any excessive failures
    excessive_failures_found = False

    # Loop through each IP and its failed login count
    for ip, count in ssh_failed_counter.items():
        if count >= SSH_FAILED_LOGIN_THRESHOLD:
            print(f"  - Potential SSH brute-force attack from {ip}: {count} failed attempts")
            excessive_failures_found = True
else:
    print("  - No SSH failed login attempts found.")

# 2. Web Failed Logins
if status_count["401"] > 0:
    print("\nWeb Failed Logins:")

    if status_count["401"] > WEB_FAILED_LOGIN_THRESHOLD:
        print(f"  - Web login warnings: {status_count['401']} total 401 Unauthorized detected.")
    else:
        print(f"  - 401 Unauthorized detected: {status_count['401']} (within normal limits)")

    # Show IP addresses associated with failed login attempts (401s)
    print("\n  IP addresses with failed logins:")
    for ip, count in ip_counter.items():
        print(f"    - {ip}: {count} total requests (check log for 401 specifics)")

else:
    print("\n  - No web failed logins detected.")

# 3. Unusual Traffic Spikes
if ip_counter:
    spike_found = False
    print("\nUnusual Traffic Spikes:")

    for ip, count in ip_counter.items():     # IPs with traffic above threshold
        if count >= TRAFFIC_SPIKE_THRESHOLD:
            print(f"  - {ip} made {count} requests (potential traffic spike)")

    for count in ip_counter.values():
        if count >= TRAFFIC_SPIKE_THRESHOLD:
            spike_found = True
            break
    if not spike_found:
        print("  - No unusual traffic spikes detected.")
else:
    print("\n  - No web IP request activity detected.")

# 4. Critical System Errors 
print("\nCritical System Errors:")
if critical_errors:
    print(f"  - {len(critical_errors)} critical error entries found.")
    for entry in critical_errors[:10]:  # Show first 10 errors
        print(f"    -> {entry}")
else:
    print("  - No critical system errors found.")

# 5. Suspicious Cron  
print("\nSuspicious Cron :")
if cron_jobs:
    print(f"  - {len(cron_jobs)} suspicious cron job entries found.")
    for entry in cron_jobs[:10]:  # Show first 10 scripts
        print(f"    -> {entry}")
else:
    print("  - No suspicious cron jobs detected.")

# 6. Status Code Summary
print("\nHTTP Status Code Summary:")
if status_count:
    for code, count in status_count.items():
        print(f"  - {code}: {count} occurrences")

print("\n=== End of LogHawk Report ===\n")
