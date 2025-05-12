import subprocess
import os
from datetime import datetime
import pandas as pd
import sys
import time
import concurrent.futures
import threading

RETRY_LIMIT = 1
RETRY_DELAY = 2

# A lock to prevent concurrent writes from stepping on each other
write_lock = threading.Lock()

def format_date(date_str):
    """
    Converts 'Oct 23 12:33:12 2023 GMT' to 'YYYY-MM-DD HH:MM:SS'.
    Returns original string if parsing fails.
    """
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return date_str

def reverse_dn_fields(dn):
    """
    Reverse the order of DN fields, e.g.:
    'C=US, O=Company, CN=www.example.com' -> 'CN=www.example.com, O=Company, C=US'
    """
    return ", ".join(reversed(dn.split(", ")))

def get_certificate_info(domain, retries=0):
    """
    Retrieves certificate info from the given domain using OpenSSL.

    - `stdin=subprocess.DEVNULL` ensures openssl s_client sees an EOF right away
      instead of hanging for interactive input.
    - If a timeout or other error occurs, we retry up to RETRY_LIMIT times.
    """
    if domain.startswith('*.'):
        domain = domain[2:]  # Strip leading '*.' if present

    print(f"Evaluating {domain}...")

    try:
        # Create a temporary directory for the PEM file
        temp_dir = f"/tmp/{domain}"
        os.makedirs(temp_dir, exist_ok=True)
        pem_path = os.path.join(temp_dir, f"{domain}.pem")

        # Build the openssl command; note the -servername to send SNI
        openssl_cmd = [
            "openssl", "s_client",
            "-connect", f"{domain}:443",
            "-servername", domain,
            "-verify_hostname", domain,
            "-showcerts"
        ]

        # Run openssl with 10-second timeout, no user input
        result = subprocess.run(
            openssl_cmd,
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL  # critical so s_client won't hang
        )

        if result.returncode != 0:
            # Nonzero return code means s_client failed to connect or had an error
            raise Exception(f"Failed to connect to {domain}, exit code: {result.returncode}")

        # Write the captured output to a PEM file
        with open(pem_path, "w") as pem_file:
            pem_file.write(result.stdout)

        # Parse certificate fields
        cert_info = {"successful": True}

        subject_cmd = f"openssl x509 -noout -subject -in {pem_path}"
        subject = subprocess.getoutput(subject_cmd).replace("subject=", "")
        cert_info["subject"] = reverse_dn_fields(subject)

        issuer_cmd = f"openssl x509 -noout -issuer -in {pem_path}"
        issuer = subprocess.getoutput(issuer_cmd).replace("issuer=", "")
        cert_info["issuer"] = reverse_dn_fields(issuer)

        serial_cmd = f"openssl x509 -noout -serial -in {pem_path}"
        serial_out = subprocess.getoutput(serial_cmd).replace("serial=", "")
        cert_info["serial"] = serial_out

        not_before_cmd = f"openssl x509 -noout -startdate -in {pem_path}"
        not_before_raw = subprocess.getoutput(not_before_cmd).replace("notBefore=", "")
        cert_info["not_before"] = format_date(not_before_raw)

        not_after_cmd = f"openssl x509 -noout -enddate -in {pem_path}"
        not_after_raw = subprocess.getoutput(not_after_cmd).replace("notAfter=", "")
        cert_info["not_after"] = format_date(not_after_raw)

        sha256_cmd = f"openssl x509 -noout -fingerprint -sha256 -in {pem_path}"
        sha256_raw = subprocess.getoutput(sha256_cmd)
        sha256_fingerprint = sha256_raw.split('=')[-1].strip().replace(":", "")
        cert_info["sha256_hash"] = sha256_fingerprint

        return cert_info

    except Exception as e:
        if retries < RETRY_LIMIT:
            print(f"Retrying {domain} (Attempt {retries + 1} of {RETRY_LIMIT})...")
            time.sleep(RETRY_DELAY)
            return get_certificate_info(domain, retries + 1)
        else:
            print(f"Error retrieving certificate from {domain}: {str(e)}")
            return {"successful": False}

def main(input_file_path):
    # Generate an output file path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base, ext = os.path.splitext(input_file_path)
    output_file_path = f"{base}-out{timestamp}{ext}"

    # Load the CSV
    df = pd.read_csv(input_file_path)
    if "dns_name" not in df.columns:
        print("Error: CSV must have a 'dns_name' column.")
        sys.exit(1)

    # Open output CSV with line-buffering or explicit flush
    # We'll do explicit flush after each line.
    with open(output_file_path, 'w') as output_file:
        # Write CSV header
        output_file.write("dns_name,Connection Successful,Subject,Issuer,Serial,Not Before,Not After,SHA256 Hash\n")
        output_file.flush()

        # Worker function to process a single domain
        def process_domain(dns_name):
            cert_info = get_certificate_info(dns_name)
            row = (
                f'"{dns_name}",'
                f'"{cert_info["successful"]}",'
                f'"{cert_info.get("subject", "")}",'
                f'"{cert_info.get("issuer", "")}",'
                f'"{cert_info.get("serial", "")}",'
                f'"{cert_info.get("not_before", "")}",'
                f'"{cert_info.get("not_after", "")}",'
                f'"{cert_info.get("sha256_hash", "")}"\n'
            )
            # Lock, then write + flush
            with write_lock:
                output_file.write(row)
                output_file.flush()

        # First test "ryandickson.me"
        print("Testing connectivity to ryandickson.me...")
        process_domain("ryandickson.me")

        # Now process each row in the CSV concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            tasks = [executor.submit(process_domain, row["dns_name"]) for _, row in df.iterrows()]
            concurrent.futures.wait(tasks)

    print(f"Processing completed. Results saved to {output_file_path}.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 processDnsNames.py [input CSV path]")
        sys.exit(1)

    main(sys.argv[1])
