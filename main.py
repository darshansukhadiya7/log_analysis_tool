import re
import csv
from collections import defaultdict

#File paths
log_file = "sample.log"
output_csv = "log_analysis_results.csv"

#Function to parse log file and extract required details
def parse_logs(file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_login_attempts = defaultdict(int)
    failed_login_threshold = 10

    with open(file_path, 'r') as file:
        for line in file:
            #Extract IP address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1

            #Extract endpoint and status code
            endpoint_match = re.search(r'"(?:GET|POST) (/[^ ]*)', line)
            status_code_match = re.search(r' (\d{3}) ', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            #Check for failed login attempts
            if status_code_match and status_code_match.group(1) == "401":
                if ip_match:
                    failed_login_attempts[ip_address] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

#Function to find most accessed endpoint
def find_most_accessed_endpoint(endpoint_requests):
    return max(endpoint_requests.items(), key=lambda x: x[1])

#Function to write results to CSV
def write_to_csv(ip_requests, most_accessed, failed_attempts, output_path):
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        #Write header and requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        #Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        #Write suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_attempts.items():
            if count > 10:
                writer.writerow([ip, count])

#Main script
ip_requests, endpoint_requests, failed_attempts = parse_logs(log_file)

most_accessed = find_most_accessed_endpoint(endpoint_requests)

print("\nIP Address Request Counts:")
for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip} - {count}")

print(f"\nMost Frequently Accessed Endpoint: {most_accessed[0]} (Accessed {most_accessed[1]} times)")

print("\nSuspicious Activity Detected:")
for ip, count in failed_attempts.items():
    if count > 10:
        print(f"{ip} - {count} failed login attempts")

write_to_csv(ip_requests, most_accessed, failed_attempts, output_csv)
print(f"\nResults saved to {output_csv}")
