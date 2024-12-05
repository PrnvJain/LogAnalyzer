import re
from collections import Counter, defaultdict
import csv

# Constants
LOG_FILE = "sample.log"
CSV_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 8  # lower threshold for testing the code 

def parse_log(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def extract_ip_addresses(log_lines):
    ip_pattern = re.compile(r"^\d+\.\d+\.\d+\.\d+")
    return [ip_pattern.match(line).group() for line in log_lines if ip_pattern.match(line)]

def extract_endpoints(log_lines):
    endpoint_pattern = re.compile(r'"[A-Z]+ (/[^ ]*)')
    return [endpoint_pattern.search(line).group(1) for line in log_lines if endpoint_pattern.search(line)]

def extract_failed_logins(log_lines):
    failed_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+).*(401|Invalid credentials)")
    failed_logins = defaultdict(int)
    for line in log_lines:
        match = failed_pattern.search(line)
        if match:
            failed_logins[match.group(1)] += 1
    return failed_logins

def count_requests_per_ip(log_lines):
    ip_addresses = extract_ip_addresses(log_lines)
    return Counter(ip_addresses).most_common()

def most_frequent_endpoint(log_lines):
    endpoints = extract_endpoints(log_lines)
    endpoint_counts = Counter(endpoints)
    return endpoint_counts.most_common(1)[0] if endpoint_counts else None

def detect_suspicious_activity(log_lines):
    failed_logins = extract_failed_logins(log_lines)
    # Flagging IPs with failed logins greater than or equal to the threshold
    return [(ip, count) for ip, count in failed_logins.items() if count >= FAILED_LOGIN_THRESHOLD]

def save_to_csv(ip_requests, most_accessed, suspicious_activity):
    with open(CSV_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Writing Requests per IP Address
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        writer.writerow([])

        # Writing Most Accessed Endpoint
        if most_accessed:
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(most_accessed)
            writer.writerow([])

        # Writing Suspicious Activity
        writer.writerow(["Suspicious Activity Detected:"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity)

if __name__ == "__main__":
    log_lines = parse_log(LOG_FILE)

    # Counting requests per IP address
    ip_requests = count_requests_per_ip(log_lines)
    print("Requests per IP Address:")
    for ip, count in ip_requests:
        print(f"{ip:<20}{count}")

    # Most frequently accessed endpoint
    most_accessed = most_frequent_endpoint(log_lines)
    if most_accessed:
        print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detecting suspicious activity
    suspicious_activity = detect_suspicious_activity(log_lines)
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity:
            print(f"{ip:<20}{count}")

    # Saving csv file
    save_to_csv(ip_requests, most_accessed, suspicious_activity)
    print(f"\nResults saved to {CSV_FILE}")
