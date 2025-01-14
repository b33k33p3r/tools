import csv
import base64
import hashlib
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path

# Function to convert Base64 string to PEM and calculate hash
def process_certificate(base64_cert):
    # Decode Base64 string
    der_cert = base64.b64decode(base64_cert)
    # Load the DER certificate
    certificate = x509.load_der_x509_certificate(der_cert, default_backend())
    # Serialize to PEM format
    pem_cert = certificate.public_bytes(serialization.Encoding.PEM)
    # Calculate SHA256 hash of the DER certificate
    sha256_hash = hashlib.sha256(der_cert).hexdigest()
    return sha256_hash, pem_cert

# Function to extract certificates from a CSV
def extract_certificates(csv_path, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(csv_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            base64_cert = row[0]  # Assume the first column contains the certificate data
            try:
                # Process the certificate
                cert_hash, pem_cert = process_certificate(base64_cert)
                # Save the PEM certificate to a file
                pem_path = output_dir / f"{cert_hash}.pem"
                with open(pem_path, 'wb') as pem_file:
                    pem_file.write(pem_cert)
                print(f"Saved: {pem_path}")
            except Exception as e:
                print(f"Error processing certificate: {e}")

# Main function to parse arguments and run the script
def main():
    parser = argparse.ArgumentParser(description="Extract and save certificates from a CSV file.")
    parser.add_argument("csv_file", help="Path to the input CSV file.")
    parser.add_argument("output_directory", help="Directory to save extracted PEM files.")
    args = parser.parse_args()

    extract_certificates(args.csv_file, args.output_directory)

if __name__ == "__main__":
    main()
