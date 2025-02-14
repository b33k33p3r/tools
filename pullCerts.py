import argparse
import base64
import hashlib
import json
import os
import requests
import time
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from construct import Struct, Byte, Int64ub, Int16ub, Enum, GreedyBytes, Int24ub, Bytes, GreedyRange, Terminated, this
from concurrent.futures import ThreadPoolExecutor, as_completed

LOG_URL = "https://ct.googleapis.com/logs/us1/argon2026h1"
VALID_OIDS = {
    "2.23.140.1.2.1": "DV",
    "2.23.140.1.2.2": "OV",
    "2.23.140.1.1": "EV",
    "2.23.140.1.2.3": "IV"
}

session = requests.Session()
session.timeout = 10  # Default timeout for all requests

# Define structures used for parsing CT log entries
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

def get_sth():
    response = session.get(f"{LOG_URL}/ct/v1/get-sth")
    response.raise_for_status()
    return response.json()

def get_entries(start, end):
    current = start
    batch_size = 1000
    while current <= end:
        batch_end = min(current + batch_size - 1, end)
        try:
            response = session.get(f"{LOG_URL}/ct/v1/get-entries?start={current}&end={batch_end}")
            response.raise_for_status()
            entries = response.json().get("entries", [])
            if not entries:
                break
            yield from entries
            time.sleep(0.5)
            if len(entries) < batch_size:
                batch_size = max(100, batch_size // 2)
            current += len(entries)
        except requests.exceptions.RequestException as e:
            print(f"Rate limit hit or request failed: {e}. Retrying with backoff...")
            time.sleep(2)

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

def find_entry_range(start_epoch, end_epoch, tree_size):
    print("Searching for the floor and ceiling.")
    def binary_search(find_floor):
        low, high = 0, tree_size - 1
        best_match = None
        while low <= high:
            mid = (low + high) // 2
            entries = list(get_entries(mid, mid))
            if not entries:
                break
            leaf_input = base64.b64decode(entries[0]["leaf_input"])
            extra_data = base64.b64decode(entries[0]["extra_data"])
            cert_data = extract_cert_from_ct_entry(leaf_input, extra_data)
            if cert_data:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                not_before = cert.not_valid_before_utc.timestamp()
                if find_floor:
                    if not_before >= start_epoch:
                        best_match, high = mid, mid - 1
                    else:
                        low = mid + 1
                else:
                    if not_before <= end_epoch:
                        best_match, low = mid, mid + 1
                    else:
                        high = mid - 1
        return best_match

    floor = binary_search(True)
    ceiling = binary_search(False)

    if floor is not None and ceiling is not None:
        print(f"Determined entry range: {floor} - {ceiling}")
    else:
        print("Floor and ceiling validation failed. Adjusting search range...")

    return floor, ceiling

def process_entry(entry, output_dir, certs_dir, errors_dir, idx):
    import os
    from lintCertsV4_3 import lint_certificate, process_certificate, initialize_results_csv

    leaf_input = base64.b64decode(entry["leaf_input"])
    extra_data = base64.b64decode(entry["extra_data"])
    cert_data = extract_cert_from_ct_entry(leaf_input, extra_data)
    if cert_data:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        sha256_hash = hashlib.sha256(cert_data).hexdigest()
        cert_path = os.path.join(certs_dir, f"{sha256_hash}.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
        print(f"Extracted and saved certificate {idx}: {cert_path}")

        # Immediately lint and process the certificate
        errors_dir = os.path.join(output_dir, "errors")
        revoked_dir = os.path.join(errors_dir, "revoked")
        crls_dir = os.path.join(output_dir, "crls")
        os.makedirs(errors_dir, exist_ok=True)
        os.makedirs(revoked_dir, exist_ok=True)
        os.makedirs(crls_dir, exist_ok=True)

        results_csv_path = initialize_results_csv(output_dir)
        process_certificate(cert_path, errors_dir, revoked_dir, crls_dir, results_csv_path)

    else:
        error_path = os.path.join(errors_dir, f"entry_{idx}.error")
        with open(error_path, "w") as f:
            f.write(json.dumps(entry))
        print(f"Failed to extract certificate for entry {idx}. Saved to {error_path}")

def main():
    parser = argparse.ArgumentParser(description="Fetch Precertificates from CT logs")
    parser.add_argument("start_epoch", type=int, help="Start epoch timestamp")
    parser.add_argument("end_epoch", type=int, help="End epoch timestamp")
    args = parser.parse_args()

    try:
        sth = get_sth()
        tree_size = sth["tree_size"]

        print("Fetching valid Precertificates from CT log...")
        floor, ceiling = find_entry_range(args.start_epoch, args.end_epoch, tree_size)

        if floor is None or ceiling is None:
            print("No matching entries found in the given time range.")
            return

        output_dir = "/Volumes/RAMDisk/cert_output_" + datetime.now().strftime('%Y%m%d_%H%M%S')
        os.makedirs(output_dir, exist_ok=True)

        certs_dir = os.path.join(output_dir, "certs")
        os.makedirs(certs_dir, exist_ok=True)

        errors_dir = os.path.join(output_dir, "errors")
        os.makedirs(errors_dir, exist_ok=True)

        idx = 1
        with ThreadPoolExecutor() as executor:
            futures = []
            for entry in get_entries(floor, ceiling):
                futures.append(executor.submit(process_entry, entry, output_dir, certs_dir, errors_dir, idx))
                idx += 1

            for future in as_completed(futures):
                future.result()

        print(f"Certificates are written incrementally and saved to {certs_dir}")

    except Exception as e:
        print(f"Unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
