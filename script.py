import csv
import re
import dns.resolver
import logging
import threading
import time
from collections import defaultdict
import os
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache to store DNS results
dns_cache = defaultdict(dict)

# Lock for thread-safe DNS cache updates
cache_lock = threading.Lock()

# DNS rate limit (queries per second)
RATE_LIMIT = 10
last_dns_query_time = time.time()

# URLs to fetch the blocklists
DISPOSABLE_EMAIL_DOMAINS_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
MALICIOUS_BLOCKLIST_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt"

# Paths to store the downloaded lists
DISPOSABLE_EMAIL_DOMAINS_FILE = 'disposable_email_blocklist.conf'
MALICIOUS_BLOCKLIST_FILE = 'malicious_blocklist.txt'

# Function to validate email syntax using regex
def is_valid_email_syntax(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

# Load blocklist from file
def load_blocklist(file_path):
    with open(file_path, 'r') as file:
        return set(line.strip() for line in file)

# Function to check if the email domain is blacklisted
def is_blacklisted_domain(email, blocklist):
    domain = email.split('@')[1]
    return domain in blocklist

# Function to check if the email domain is from a known disposable email provider
def is_disposable_email(email, disposable_domains):
    domain = email.split('@')[1]
    return domain in disposable_domains

# Function to check if the email is a role-based email address
def is_role_based_email(email):
    role_based_prefixes = set([
        "admin", "administrator", "webmaster", "hostmaster", "postmaster", "support", "contact",
    ])
    prefix = email.split('@')[0]
    return prefix in role_based_prefixes

# Function to check if the domain has valid DNS records with caching and rate limiting
def has_valid_domain(email):
    domain = email.split('@')[1]
    with cache_lock:
        if domain in dns_cache and 'A' in dns_cache[domain]:
            return dns_cache[domain]['A']
    
    # Rate limiting
    global last_dns_query_time
    current_time = time.time()
    if current_time - last_dns_query_time < 1.0 / RATE_LIMIT:
        time.sleep(1.0 / RATE_LIMIT - (current_time - last_dns_query_time))
    last_dns_query_time = time.time()

    try:
        dns.resolver.resolve(domain, 'A')
        with cache_lock:
            dns_cache[domain]['A'] = True
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        with cache_lock:
            dns_cache[domain]['A'] = False
        return False

# Function to check if the domain has MX records with caching and rate limiting
def has_mx_record(email):
    domain = email.split('@')[1]
    with cache_lock:
        if domain in dns_cache and 'MX' in dns_cache[domain]:
            return dns_cache[domain]['MX']

    # Rate limiting
    global last_dns_query_time
    current_time = time.time()
    if current_time - last_dns_query_time < 1.0 / RATE_LIMIT:
        time.sleep(1.0 / RATE_LIMIT - (current_time - last_dns_query_time))
    last_dns_query_time = time.time()

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        with cache_lock:
            dns_cache[domain]['MX'] = len(mx_records) > 0
        return len(mx_records) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        with cache_lock:
            dns_cache[domain]['MX'] = False
        return False

# Function to download files using requests if they don't exist
def download_file(url, output_file):
    if not os.path.exists(output_file):
        response = requests.get(url)
        response.raise_for_status()
        with open(output_file, 'wb') as file:
            file.write(response.content)

# Read emails from CSV, validate them, and update the input CSV
def validate_emails(input_csv, output_csv, disposable_file, malicious_file):
    # Download the blocklists if they don't exist
    download_file(DISPOSABLE_EMAIL_DOMAINS_URL, disposable_file)
    download_file(MALICIOUS_BLOCKLIST_URL, malicious_file)

    # Load disposable email domains and malicious blocklist
    disposable_domains = load_blocklist(disposable_file)
    malicious_blocklist = load_blocklist(malicious_file)
    
    temp_csv = 'temp_emails.csv'
    with open(input_csv, mode='r') as infile, open(output_csv, mode='w', newline='') as outfile, open(temp_csv, mode='w', newline='') as temp_file:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        temp_writer = csv.DictWriter(temp_file, fieldnames=fieldnames)
        writer.writeheader()
        temp_writer.writeheader()

        total_rows = sum(1 for row in reader)
        infile.seek(0)  # Reset reader to the start of the file
        next(reader)    # Skip header

        for count, row in enumerate(reader, 1):
            email = row['email']
            status = row['status'].lower()
            if status == "blocklisted":
                temp_writer.writerow(row)
                continue
            if (not is_valid_email_syntax(email) or 
                is_blacklisted_domain(email, malicious_blocklist) or 
                is_disposable_email(email, disposable_domains) or 
                is_role_based_email(email) or 
                not has_valid_domain(email) or 
                not has_mx_record(email)):
                writer.writerow(row)
            else:
                temp_writer.writerow(row)

            # Log progress
            progress = (count / total_rows) * 100
            logging.info(f'Progress: {progress:.2f}% ({count}/{total_rows})')

    # Replace the original input CSV with the temporary file
    os.replace(temp_csv, input_csv)

# Paths to the input and output CSV files
input_csv = 'input_emails.csv'
output_csv = 'blacklisted_emails.csv'

# Run the email validation
validate_emails(input_csv, output_csv, DISPOSABLE_EMAIL_DOMAINS_FILE, MALICIOUS_BLOCKLIST_FILE)
