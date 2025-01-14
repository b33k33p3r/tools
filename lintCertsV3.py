import argparse
import sys
import os
import shutil
import requests
import base64
import hashlib
import csv
import urllib.parse
import time
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, GreedyBytes, GreedyRange, Terminated, this
import requests

session = requests.Session()
session.timeout = 10  # Default timeout for all requests

# Define structures used for parsing
MerkleTreeHeader = Struct(
    "Version" / Byte,
    "MerkleLeafType" / Byte,
    "Timestamp" / Int64ub,
    "LogEntryType" / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry" / GreedyBytes
)

Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
    Terminated
)

# OIDs for IV, DV, OV, and EV
VALID_OIDS = {
    "2.23.140.1.2.1": "DV",  # DV
    "2.23.140.1.2.2": "OV",  # OV
    "2.23.140.1.1": "EV",    # EV
    "2.23.140.1.2.3": "IV"   # IV
}

def parse_arguments():
    parser = argparse.ArgumentParser(description="Lint certificates using provided input data.")

    # Add mutually exclusive group for certificate data input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-ct", action="store_true", help="Specify that certificate data will be provided directly.")
    input_group.add_argument("-dir", help="Specify a directory containing certificates.")
    input_group.add_argument("-csv", help="Specify a CSV file with certificate data.")

    # Add optional argument for checking status
    parser.add_argument("-check_status", action="store_true",
                        help="Check the status of certificates during linting.")

    # Add optional argument for results directory
    parser.add_argument("-results_dir", help="Specify the directory to store results. Default is script's location.")

    return parser.parse_args()

def setup_results_directory(base_dir):
    # Use provided directory or default to script's location
    if not base_dir:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    # Create a timestamped directory
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_dir = os.path.join(base_dir, f"results_{timestamp}")
    os.makedirs(results_dir, exist_ok=True)

    # Create subdirectories
    for subdir in ["certificates", "crls", "errors"]:
        os.makedirs(os.path.join(results_dir, subdir), exist_ok=True)

    # Add revoked subdirectory under errors
    os.makedirs(os.path.join(results_dir, "errors", "revoked"), exist_ok=True)

    return results_dir

def initialize_results_csv(results_dir):
    results_csv_path = os.path.join(results_dir, "results.csv")
    if not os.path.exists(results_csv_path):
        with open(results_csv_path, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=[
                'SHA256HashHex', 'Issuer', 'SerialNumberHex',
                'NotBefore', 'NotAfter', 'Revocation Status',
                'Revocation Reason', 'Revocation Date', 'Linting Results'
            ])
            writer.writeheader()
    return results_csv_path

def append_to_results_csv(results_csv_path, row):
    with open(results_csv_path, mode='a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=row.keys())
        writer.writerow(row)

def extract_certificate_details(cert):
    return {
        'Issuer': cert.issuer.rfc4514_string(),
        'SerialNumberHex': hex(cert.serial_number)[2:].upper(),
        'NotBefore': cert.not_valid_before_utc,
        'NotAfter': cert.not_valid_after_utc
    }

def fetch_revocation_info(cert, crls_dir):
    try:
        crl_dist_points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for point in crl_dist_points:
            for name in point.full_name:
                if name.value.startswith("http"):
                    print(f"Fetching CRL from: {name.value}")
                    response = session.get(name.value, timeout=10)
                    if response.status_code == 200:
                        # Save the CRL to the crls directory
                        crl_filename = os.path.basename(name.value)
                        crl_path = os.path.join(crls_dir, crl_filename)
                        with open(crl_path, 'wb') as crl_file:
                            crl_file.write(response.content)
                        print(f"Saved CRL to: {crl_path}")

                        # Load and process the CRL
                        crl = x509.load_der_x509_crl(response.content, default_backend())
                        for revoked_cert in crl:
                            if revoked_cert.serial_number == cert.serial_number:
                                reason = revoked_cert.extensions.get_extension_for_class(x509.CRLReason).value.reason
                                return "REVOKED", reason, revoked_cert.revocation_date_utc
    except Exception as e:
        print(f"Error fetching revocation info for certificate with serial: {cert.serial_number}: {e}")
    return "", "", ""


def lint_certificate(encoded_cert):
    url = 'http://localhost:8080/lintcert'
    encoded_cert = urllib.parse.quote(encoded_cert, safe='')
    data = f"b64input={encoded_cert}&format=text&severity=error&profile=autodetect"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        response = requests.post(url, data=data, headers=headers)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return f"Linting failed with status {response.status_code}"
    except Exception as e:
        return f"Linting error: {e}"

def process_certificate(cert_path, errors_dir, revoked_dir, results_csv_path):
    try:
        print(f"Processing certificate file: {cert_path}")
        with open(cert_path, 'rb') as f:
            pem_data = f.read()

        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        sha256_hash = hashlib.sha256(cert.tbs_certificate_bytes).hexdigest()

        cert_details = extract_certificate_details(cert)
        print(f"Certificate details: SHA256={sha256_hash}, Issuer={cert_details['Issuer']}")

        # Perform linting
        linting_result = lint_certificate(base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode())
        if not linting_result:
            print(f"No linting errors found for certificate: {sha256_hash}")
            os.remove(cert_path)  # Remove certificates without linting errors
            return

        print(f"Linting errors found for certificate: {sha256_hash}")

        # Perform revocation checking only if linting errors are present
        revocation_status, revocation_reason, revocation_date = fetch_revocation_info(cert)

        # Prepare the CSV row
        row = {
            'SHA256HashHex': sha256_hash,
            'Issuer': cert_details['Issuer'],
            'SerialNumberHex': cert_details['SerialNumberHex'],
            'NotBefore': cert_details['NotBefore'],
            'NotAfter': cert_details['NotAfter'],
            'Revocation Status': revocation_status,
            'Revocation Reason': revocation_reason,
            'Revocation Date': revocation_date,
            'Linting Results': linting_result
        }
        append_to_results_csv(results_csv_path, row)

        # Move the certificate based on revocation status
        if revocation_status == "REVOKED":
            shutil.move(cert_path, os.path.join(revoked_dir, os.path.basename(cert_path)))
        else:
            shutil.move(cert_path, os.path.join(errors_dir, os.path.basename(cert_path)))

        print(f"Processed and logged certificate: {sha256_hash}")

    except Exception as e:
        print(f"Error processing certificate {cert_path}: {e}")

def fetch_certificates_from_ct(results_dir):
    certs_dir = os.path.join(results_dir, "certificates")
    processed_hashes = set()

    def fetch_ct_log_urls():
        log_list_url = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
        try:
            response = requests.get(log_list_url)
            if response.status_code == 200:
                log_list = response.json()
                urls = []
                for operator in log_list.get("operators", []):
                    for log in operator.get("logs", []):
                        url = log.get("url")
                        if url:
                            urls.append(url)
                print(f"Fetched {len(urls)} CT log URLs.")
                return urls
            else:
                print(f"Failed to fetch log list from {log_list_url}. Status code: {response.status_code}")
                return []
        except Exception as e:
            print(f"Error fetching CT log list: {str(e)}")
            return []

    while True:
        ct_logs = fetch_ct_log_urls()
        if not ct_logs:
            print("No CT log URLs retrieved. Exiting.")
            return

        for ct_log_url in ct_logs:
            print(f"Fetching certificates from CT log: {ct_log_url}")
            try:
                sth_url = f"{ct_log_url}/ct/v1/get-sth"
                response = requests.get(sth_url)
                if response.status_code != 200:
                    print(f"Failed to fetch STH for {ct_log_url}. Status code: {response.status_code}")
                    continue

                tree_size = response.json().get("tree_size", 0)
                if tree_size == 0:
                    print(f"No entries in CT log: {ct_log_url}")
                    continue

                start_index = max(0, tree_size - 100)
                entries_url = f"{ct_log_url}/ct/v1/get-entries?start={start_index}&end={tree_size - 1}"
                entries_response = requests.get(entries_url)

                if entries_response.status_code != 200:
                    print(f"Failed to fetch entries for {ct_log_url}. Status code: {entries_response.status_code}")
                    continue

                entries = entries_response.json().get("entries", [])
                for entry in entries:
                    try:
                        leaf_input = base64.b64decode(entry["leaf_input"])
                        extra_data = base64.b64decode(entry["extra_data"])

                        cert_data = extract_cert_from_ct_entry(leaf_input, extra_data)
                        if cert_data:
                            sha256_hash = hashlib.sha256(cert_data).hexdigest()
                            if sha256_hash in processed_hashes:
                                continue

                            cert = x509.load_der_x509_certificate(cert_data, default_backend())

                            if is_certificate_valid(cert):
                                pem_cert = cert.public_bytes(serialization.Encoding.PEM)
                                output_filename = f"{sha256_hash}.pem"
                                full_path = os.path.join(certs_dir, output_filename)

                                with open(full_path, "wb") as pem_file:
                                    pem_file.write(pem_cert)

                                processed_hashes.add(sha256_hash)
                    except Exception as inner_e:
                        print(f"Error processing entry: {str(inner_e)}")

            except Exception as e:
                print(f"Error fetching from {ct_log_url}: {str(e)}")

        lint_certificates_in_directory(results_dir)

        if not os.listdir(certs_dir):
            print("Certificates directory is empty. Re-querying logs for new certificates...")
            time.sleep(30)

def extract_cert_from_ct_entry(leaf_input, extra_data):
    try:
        leaf_cert = MerkleTreeHeader.parse(leaf_input)
        if leaf_cert.LogEntryType == "X509LogEntryType":
            cert_data = Certificate.parse(leaf_cert.Entry).CertData
        else:
            cert_data = Certificate.parse(extra_data).CertData
        return cert_data
    except Exception as e:
        print(f"Error extracting certificate from CT entry: {str(e)}")
        return None

def is_certificate_valid(cert):
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
        return False

    try:
        for ext in cert.extensions:
            if isinstance(ext.value, x509.CertificatePolicies):
                for policy in ext.value:
                    if policy.policy_identifier.dotted_string in VALID_OIDS:
                        return True
    except Exception as e:
        print(f"Error checking OIDs: {e}")

    return False

def lint_certificates_in_directory(results_dir):
    certs_dir = os.path.join(results_dir, "certificates")
    errors_dir = os.path.join(results_dir, "errors")
    revoked_dir = os.path.join(errors_dir, "revoked")
    results_csv_path = initialize_results_csv(results_dir)

    def status_indicator():
        while True:
            time.sleep(10)
            remaining_files = len(os.listdir(certs_dir))
            print(f"Certificates remaining to process: {remaining_files}")
            if remaining_files == 0:
                break

    import threading
    indicator_thread = threading.Thread(target=status_indicator, daemon=True)
    indicator_thread.start()

    for cert_file in os.listdir(certs_dir):
        cert_path = os.path.join(certs_dir, cert_file)
        if os.path.isfile(cert_path):
            process_certificate(cert_path, errors_dir, revoked_dir, results_csv_path)

def main():
    args = parse_arguments()

    results_dir = setup_results_directory(args.results_dir)
    print(f"Results will be stored in: {results_dir}")

    if args.ct:
        print("Lint certificates from Certificate Transparency logs: -ct")
        fetch_certificates_from_ct(results_dir)
    elif args.dir:
        print(f"Lint b64-encoded certificates in a directory: {args.dir}")
        copy_certificates_to_results(args.dir, results_dir)
        lint_certificates_in_directory(results_dir)
    elif args.csv:
        print(f"Lint certificates from a CSV file produced by PKI Monitoring: {args.csv}")
        process_csv_file(args.csv, results_dir)

    if args.check_status:
        print("Certificate status checking enabled.")
    else:
        print("Certificate status checking not enabled.")

if __name__ == "__main__":
    main()
