import os
import csv
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Define the CRL directory and output file
crl_dir = "/Users/rcd/Desktop/getCRLOut/crls/done"
output_csv = "/Users/rcd/Desktop/crl_issuers.csv"

def get_issuer_from_crl(crl_path):
    """
    Extract the issuer from the CRL file.
    """
    try:
        with open(crl_path, "rb") as crl_file:
            crl = x509.load_der_x509_crl(crl_file.read(), default_backend())
            return crl.issuer.rfc4514_string()
    except Exception as e:
        print(f"Error processing {crl_path}: {e}")
        return "Error"

def process_crls_to_csv(crl_dir, output_csv):
    """
    Process all .crl files in the given directory and write filename and issuer to CSV.
    """
    # Prepare CSV file for writing
    with open(output_csv, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Filename", "Issuer"])  # Write header row

        # Loop through CRL files
        for filename in os.listdir(crl_dir):
            if filename.endswith(".crl"):
                crl_path = os.path.join(crl_dir, filename)
                issuer = get_issuer_from_crl(crl_path)
                writer.writerow([filename, issuer])  # Write data row
                print(f"Processed: {filename}")

# Run the script
if __name__ == "__main__":
    process_crls_to_csv(crl_dir, output_csv)
    print(f"CSV file generated at: {output_csv}")
