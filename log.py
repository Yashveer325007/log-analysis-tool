import re
import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
            if ip_match:
                ip_address = ip_match.group()
                ip_requests[ip_address] += 1

            endpoint_match = re.search(r'\"(?:GET|POST) (/\S+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            if "401" in line or "Invalid credentials" in line:
                if ip_match:
                    failed_login_attempts[ip_address] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

def save_to_csv(ip_requests, most_accessed, failed_logins, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in failed_logins:
            writer.writerow([ip, count])

def main():
    log_file_path = "sample_log.txt"
    output_csv_file = "log_analysis_results.csv"

    ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(log_file_path)

    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
    suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD]

    print("Requests per IP Address:")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips:
        print(f"{ip:<20} {count}")

    save_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_ips, output_csv_file)
    print(f"\nResults saved to {output_csv_file}")

if __name__ == "__main__":
    main()
