
import subprocess
import os
from datetime import datetime
import pandas as pd
import sys
import concurrent.futures
import time

RETRY_LIMIT = 1  # Number of times to retry failed domains
RETRY_DELAY = 2  # Seconds to wait before retrying

def format_date(date_str):
    """
    Converts the OpenSSL date format (e.g., 'Oct 23 12:33:12 2023 GMT')
    into a more standard format: 'YYYY-MM-DD HH:MM:SS'
    """
    try:
        date_obj = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        return date_obj.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        return date_str

def reverse_dn_fields(dn):
    """
    Reverses the order of the DN fields (subject or issuer).
    Example: 'C=US, O=Company, CN=www.example.com' becomes 'CN=www.example.com, O=Company, C=US'
    """
    return ", ".join(reversed(dn.split(", ")))

def get_certificate_info(domain, retries=0):
    """
    Uses openssl to retrieve certificate information from the given domain.
    If the connection fails, retries up to RETRY_LIMIT times.
    Returns a dictionary with the relevant certificate details if successful, otherwise False.
    """
    if domain.startswith('*.'):
        domain = domain[2:]  # Strip leading wildcard
    print(f"Evaluating {domain}...")

    try:
        temp_dir = f"/tmp/{domain}"
        os.makedirs(temp_dir, exist_ok=True)

        # Run openssl command to retrieve the certificate
        openssl_cmd = f"timeout 10 openssl s_client -connect {domain}:443 -verify_hostname {domain} -showcerts"
        result = subprocess.run(openssl_cmd, shell=True, capture_output=True, text=True)

        if "CONNECTED" not in result.stdout:
            raise Exception(f"Failed to connect to {domain}")

        # Save the certificate to a temporary file
        pem_path = os.path.join(temp_dir, f"{domain}.pem")
        with open(pem_path, "w") as pem_file:
            pem_file.write(result.stdout)

        # Extract certificate details using openssl
        cert_info = {}
        cert_info["successful"] = True
        subject = subprocess.getoutput(f"openssl x509 -noout -subject -in {pem_path}").replace("subject=", "")
        issuer = subprocess.getoutput(f"openssl x509 -noout -issuer -in {pem_path}").replace("issuer=", "")
        cert_info["subject"] = reverse_dn_fields(subject)
        cert_info["issuer"] = reverse_dn_fields(issuer)
        cert_info["serial"] = subprocess.getoutput(f"openssl x509 -noout -serial -in {pem_path}").replace("serial=", "")
        not_before = subprocess.getoutput(f"openssl x509 -noout -startdate -in {pem_path}").replace("notBefore=", "")
        cert_info["not_before"] = format_date(not_before)
        not_after = subprocess.getoutput(f"openssl x509 -noout -enddate -in {pem_path}").replace("notAfter=", "")
        cert_info["not_after"] = format_date(not_after)

        # Correctly remove "sha256 Fingerprint=" and colons from the hash
        sha256_hash = subprocess.getoutput(f"openssl x509 -noout -fingerprint -sha256 -in {pem_path}")
        sha256_hash = sha256_hash.split('=')[-1].strip().replace(":", "")
        cert_info["sha256_hash"] = sha256_hash

        return cert_info

    except Exception as e:
        if retries < RETRY_LIMIT:
            print(f"Retrying {domain} (Attempt {retries + 1} of {RETRY_LIMIT})...")
            time.sleep(RETRY_DELAY)
            return get_certificate_info(domain, retries + 1)
        else:
            print(f"Error retrieving certificate from {domain}: {str(e)}")
            return {"successful": False}

if __name__ == "__main__":
    # Ensure correct usage with one argument: input file
    if len(sys.argv) != 2:
        print("Usage: python3 processDnsNames.py [input file path]")
        sys.exit(1)

    # Get the input file path from the command line argument
    input_file_path = sys.argv[1]

    # Generate the output file path by prepending "-out[timestamp]" to the input file's name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base, ext = os.path.splitext(input_file_path)
    output_file_path = f"{base}-out{timestamp}{ext}"

    # Load the CSV file
    df = pd.read_csv(input_file_path)

    # Open the output file for incremental writing
    with open(output_file_path, 'w') as output_file:
        # Write the headers to the output file
        output_file.write('dns_name,SHA256HashHex,Connection Successful,Subject,Issuer,Serial,Not Before,Not After,SHA256 Hash\n')

        # Define a function to process each DNS name and write the result to the output file
        def process_dns_name(row):
            dns_name = row['dns_name']

            # Get certificate information using openssl with retry
            cert_info = get_certificate_info(dns_name)

            # Build the result row
            result_row = f'"{row["dns_name"]}","{row["SHA256HashHex"]}","{cert_info["successful"]}","{cert_info.get("subject", "")}","{cert_info.get("issuer", "")}","{cert_info.get("serial", "")}","{cert_info.get("not_before", "")}","{cert_info.get("not_after", "")}","{cert_info.get("sha256_hash", "")}"\n'

            # Write the result to the output file incrementally
            output_file.write(result_row)

        # Use ThreadPoolExecutor to make concurrent connections
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(process_dns_name, row): row for _, row in df.iterrows()}

            # Wait for all futures to complete
            concurrent.futures.wait(futures)

    print(f"Processing completed. Results saved to {output_file_path}.")
