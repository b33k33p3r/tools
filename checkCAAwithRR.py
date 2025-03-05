import argparse
import subprocess
import os
import time
import threading
import datetime
import csv
import logging

# Configure logging
logging.basicConfig(filename="caa_rrsig_debug.log", level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

def fetch_caa_records(domain):
    """Fetches and cleans CAA records using dig."""
    try:
        result = subprocess.run(
            ["dig", "@8.8.8.8", domain, "CAA", "+dnssec", "+multi", "+nocmd", "+nostats"],
            capture_output=True, text=True
        )
        logging.debug(f"dig CAA output for {domain}: {result.stdout}")

        # Extract and clean CAA values
        records = [
            line.strip().split(' ', 2)[-1].replace('"', '').replace("CAA 0 ", "").strip()
            for line in result.stdout.strip().split('\n')
            if "issue" in line
        ]
        return records if records else []
    except Exception as e:
        logging.error(f"Error fetching CAA records for {domain}: {e}")
        return []

def get_rrsig_for_caa(domain):
    """Fetches RRSIG records specifically for CAA using dig, extracting the inception timestamp."""
    while domain:
        try:
            result = subprocess.run(
                ["dig", "@8.8.8.8", domain, "CAA", "+dnssec", "+multi", "+nocmd", "+nostats"],
                capture_output=True, text=True
            )
            logging.debug(f"dig RRSIG CAA output for {domain}: {result.stdout}")

            lines = result.stdout.strip().split('\n')
            timestamps = []
            capture_next = False  # Flag to capture next line for timestamps

            for i, line in enumerate(lines):
                if " RRSIG CAA " in line:
                    capture_next = True  # Mark that the next line contains timestamps
                    logging.debug(f"Detected RRSIG CAA start line: {line}")
                elif capture_next:
                    # This is the next line; extract the timestamps
                    parts = line.split()
                    if len(parts) >= 2:
                        expiration_timestamp = parts[0]  # Expiration timestamp (field 1)
                        inception_timestamp = parts[1]  # Inception timestamp (field 2)
                        timestamps.append(inception_timestamp)  # We now extract **inception**
                        logging.debug(f"Extracted RRSIG timestamps: Expiration={expiration_timestamp}, Inception={inception_timestamp}")
                    capture_next = False  # Reset the flag

            if timestamps:
                best_inception = min(timestamps)  # Find the earliest inception (effective) date
                logging.info(f"Found RRSIG for {domain}, earliest effective date: {best_inception}")
                return domain, best_inception
            else:
                logging.warning(f"No valid RRSIG inception timestamps found for {domain}")
                return domain, "No Valid RRSIG"

        except Exception as e:
            logging.error(f"Error fetching RRSIG for {domain}: {e}")
            return domain, "Error"

        if '.' in domain:
            domain = domain.split('.', 1)[1]  # Move up one level
        else:
            break
    return "None", "None"

def walk_caa_tree(domain):
    """Walks up the domain tree to find the next available CAA record."""
    while domain:
        records = fetch_caa_records(domain)
        if records:
            return domain, records
        if '.' in domain:
            domain = domain.split('.', 1)[1]
        else:
            break
    return None, []

def main(file_path):
    """Reads domains from a file, fetches CAA and RRSIG records, then writes output to CSV."""
    if not os.path.isfile(file_path):
        return

    with open(file_path, 'r') as file:
        domains = [line.strip() for line in file if line.strip()]

    if not domains:
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_filename = f"caaCheck-{timestamp}-output.csv"

    total_domains = len(domains)
    processed_count = 0

    def status_reporter():
        """Reports progress every 5 minutes."""
        while processed_count < total_domains:
            remaining = total_domains - processed_count
            print(f"Processing... {remaining} domains remaining.")
            time.sleep(300)

    reporter_thread = threading.Thread(target=status_reporter)
    reporter_thread.daemon = True
    reporter_thread.start()

    with open(output_filename, "w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Domain", "CAA Present?", "CAA Values", "CAA Record From", "CAA RRSIG Present?", "CAA RRSIG Values From", "CAA RRSIG Timestamp"])

        for domain in domains:
            records = fetch_caa_records(domain)
            caa_present = "Yes" if records else "No"

            # Walk up the tree if no CAA found
            next_caa_location, next_caa_records = walk_caa_tree(domain) if not records else (domain, records)
            caa_record_from = next_caa_location if next_caa_location else "None"
            caa_values_from_parent = ", ".join(next_caa_records) if next_caa_records else "None"

            # Ensure inherited CAA is marked as "Yes"
            if next_caa_records:
                caa_present = "Yes"

            rrsig_location, rrsig_timestamp = get_rrsig_for_caa(caa_record_from)
            rrsig_present = "Yes" if rrsig_timestamp not in ["None", ""] else "No"

            csv_writer.writerow([
                domain, caa_present, caa_values_from_parent, caa_record_from, rrsig_present, rrsig_location if rrsig_present == "Yes" else "None", rrsig_timestamp
            ])
            csv_file.flush()

            print(f"Processed: {domain} - CAA Present: {caa_present} - CAA Values: {caa_values_from_parent} - "
                  f"CAA Record From: {caa_record_from} - RRSIG Present: {rrsig_present} - "
                  f"RRSIG From: {rrsig_location if rrsig_present == 'Yes' else 'None'} - "
                  f"RRSIG Date: {rrsig_timestamp if rrsig_timestamp not in ['None', '', 'N/A'] else 'No Valid RRSIG'}")

            logging.info(f"Processed: {domain} - CAA Present: {caa_present} - CAA Values: {caa_values_from_parent} - CAA Record From: {caa_record_from} - RRSIG Present: {rrsig_present} - RRSIG From: {rrsig_location if rrsig_present == 'Yes' else 'None'} - RRSIG Date: {rrsig_timestamp}")
            processed_count += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fetch CAA and RRSIG records for a list of domains and save to CSV.')
    parser.add_argument('file_path', help='Path to the file containing domain names.')
    args = parser.parse_args()
    main(args.file_path)
