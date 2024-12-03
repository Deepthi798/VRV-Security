import re
import csv
from collections import Counter, defaultdict

def analyze_log_file(log_file, output_csv, threshold=10):
    # Initialize counters and data structures
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_login_attempts = defaultdict(int)
    
    # Regular expressions for parsing
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    endpoint_pattern = re.compile(r'"(?:GET|POST) (.*?) HTTP')
    failed_login_pattern = re.compile(r'401|Invalid credentials')

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP addresses
            ip_match = ip_pattern.search(line)
            if ip_match:
                ip_address = ip_match.group()
                ip_counter[ip_address] += 1
            
            # Extract endpoints
            endpoint_match = endpoint_pattern.search(line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counter[endpoint] += 1
            
            # Detect failed login attempts
            if failed_login_pattern.search(line) and ip_match:
                failed_login_attempts[ip_address] += 1
    
    # Sort data for output
    sorted_ips = ip_counter.most_common()
    most_accessed_endpoint = endpoint_counter.most_common(1)[0] if endpoint_counter else ("None", 0)
    suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > threshold]

    # Display results
    print("Requests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in sorted_ips:
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips:
        print(f"{ip:20} {count}")
    
    # Write results to CSV
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(sorted_ips)
        
        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        
        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips)

# Save the sample log file for demonstration
sample_log = """192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312
198.51.100.23 - - [03/Dec/2024:10:12:38 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:39 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:40 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:41 +0000] "GET /dashboard HTTP/1.1" 200 1024
198.51.100.23 - - [03/Dec/2024:10:12:42 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024
203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
"""

with open("sample.log", "w") as f:
    f.write(sample_log)

# Analyze the sample log file
analyze_log_file("sample.log", "log_analysis_results.csv")
