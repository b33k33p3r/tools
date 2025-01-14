import os
import csv
import requests
import time
from datetime import datetime
from io import StringIO
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Create a folder for storing certificates
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
folder_name = f"certs-{timestamp}"
os.makedirs(folder_name, exist_ok=True)

# CSV file to log the certificate details
csv_file = f"certs_report_{timestamp}.csv"
csv_headers = [
    "Certificate Hash", "notBefore", "notAfter", "CRL Revoked",
    "CRL Revocation Reason"
]

# Initialize the CSV file with headers
with open(csv_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(csv_headers)

# Function to extract SHA256 hash from crt.sh URL
def extract_sha256(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if 'sha256' in query_params:
        return query_params['sha256'][0]
    return None

# Function to download a certificate and save it to disk
def download_certificate(sha256_hash):
    url = f"https://crt.sh/?d={sha256_hash}"
    retries = 5
    while retries > 0:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            file_path = os.path.join(folder_name, f"{sha256_hash}.crt")
            with open(file_path, 'wb') as cert_file:
                cert_file.write(response.content)
            return file_path, sha256_hash, True
        except requests.exceptions.RequestException as e:
            print(f"Error downloading {sha256_hash}: {e}")
            retries -= 1
            time.sleep(2)
    return None, sha256_hash, False

# Function to extract certificate details and check CRL status
def process_certificate(file_path, sha256_hash):
    with open(file_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Get the notBefore and notAfter dates in UTC
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    # Initialize default values for CRL check
    crl_revoked, crl_reason = check_crl(cert)

    # Log the certificate data into the CSV
    with open(csv_file, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            sha256_hash, not_before, not_after, crl_revoked, crl_reason
        ])

# Function to check CRL status of the certificate
def check_crl(cert):
    try:
        crl_dp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        for dp in crl_dp.value:
            crl_url = dp.full_name[0].value
            crl_response = requests.get(crl_url)
            crl = x509.load_der_x509_crl(crl_response.content, default_backend())
            for revoked_cert in crl:
                if revoked_cert.serial_number == cert.serial_number:
                    # Check if reason is available; default to None if not present
                    reason = getattr(revoked_cert, 'reason', None)
                    return True, reason
        return False, None
    except x509.ExtensionNotFound:
        return "NA", None  # No CRLDP available in the cert
    except Exception as e:
        print(f"Error checking CRL for {cert}: {e}")
        return "Unknown", "Unknown"


# Function to handle certificate processing and CRL checks
def download_and_process_certificate(sha256_hash):
    file_path, sha256_hash, success = download_certificate(sha256_hash)
    if success and file_path:
        process_certificate(file_path, sha256_hash)
    else:
        print(f"Failed to download or process certificate {sha256_hash}")

# Fetch and process a file from a URL
def fetch_file_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text

# Parse crt.sh links from a plain text or CSV file
def process_links(file_content):
    return file_content.strip().splitlines()

# Concurrent download and processing of certificates
def download_all_certificates_concurrently(links, max_workers=3):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(download_and_process_certificate, extract_sha256(link)): link for link in links}
        for future in as_completed(futures):
            future.result()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Download certificates from crt.sh and log revocation status to CSV.")
    parser.add_argument('file_url', type=str, help="The URL of the file containing crt.sh links")
    args = parser.parse_args()

    # Fetch and process the file from the provided URL
    file_content = fetch_file_from_url(args.file_url)
    crt_links = process_links(file_content)
    print(f"Total CRT.sh URLs: {len(crt_links)}")

    # Download and process certificates concurrently
    download_all_certificates_concurrently(crt_links)
