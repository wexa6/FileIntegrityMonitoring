# fim_tool.py

import os
import hashlib
import json
import argparse
import configparser
import logging
from datetime import datetime

# --- Imports for Email Alerting ---
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

CONFIG_FILE = 'config.ini'

# --- CORE UTILITY FUNCTIONS ---

def load_config():
    """Loads settings from config.ini"""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"Configuration file '{CONFIG_FILE}' not found. Please create it.")
    config = configparser.ConfigParser(interpolation=None)
    config.read(CONFIG_FILE)
    return config

def setup_logging(log_file):
    """Configures logging to both console and a file."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
    )

def get_monitored_paths(config):
    """Reads and expands paths from the config file, ensuring they exist."""
    paths_str = config.get('FIM', 'monitor_paths', fallback='')
    raw_paths = [os.path.expandvars(p.strip()) for p in paths_str.split(',') if p.strip()]

    existing_paths = []
    for path in raw_paths:
        if os.path.exists(path):
            existing_paths.append(path)
        else:
            logging.warning(f"Configured path not found, skipping: {path}")

    return existing_paths

def calculate_hash(filepath, algorithm):
    """Calculates the hash of a file using the specified algorithm."""
    try:
        h = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logging.warning(f"Could not hash {filepath}: {e}")
        return None

def generate_hashes_from_paths(paths_to_monitor, algorithm):
    """Generates a dictionary of file paths and their hashes."""
    file_hashes = {}
    logging.info("Starting hash generation process...")
    for path in paths_to_monitor:
        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path):
            file_hash = calculate_hash(abs_path, algorithm)
            if file_hash:
                file_hashes[abs_path] = file_hash
        elif os.path.isdir(abs_path):
            for root, _, files in os.walk(abs_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    file_hash = calculate_hash(filepath, algorithm)
                    if file_hash:
                        file_hashes[filepath] = file_hash
    logging.info("Hash generation complete.")
    return file_hashes

# --- Email Alerting Function (The Only Alert Method) ---

def send_email_alert(config, subject, body):
    """Sends an email notification."""
    if not config.getboolean('Email', 'send_email_alerts', fallback=False):
        logging.info("Email alerts are disabled in the configuration. No alert sent.")
        return

    # Securely load password from environment variable
    smtp_password = os.environ.get('FIM_SMTP_PASSWORD')
    if not smtp_password:
        logging.error("Failed to send email: 'FIM_SMTP_PASSWORD' environment variable not set.")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = config['Email']['smtp_user']
        msg['To'] = config['Email']['recipient_email']
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(config['Email']['smtp_server'], int(config['Email']['smtp_port']))
        server.starttls()
        server.login(config['Email']['smtp_user'], smtp_password)
        server.send_message(msg)
        server.quit()
        logging.info(f"Alert email successfully sent to {config['Email']['recipient_email']}.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

# --- FIM ACTIONS: BASELINE AND SCAN ---

def create_baseline(config):
    """Creates a baseline of file hashes."""
    baseline_file = config['FIM']['baseline_file']
    algorithm = config['FIM']['hash_algorithm']
    paths_to_monitor = get_monitored_paths(config)
    if os.path.exists(baseline_file):
        if input(f"Baseline file '{baseline_file}' exists. Overwrite? (y/n): ").lower() != 'y':
            print("Baseline creation cancelled.")
            return

    logging.info("--- Creating New Baseline ---")
    baseline_data = generate_hashes_from_paths(paths_to_monitor, algorithm)
    if not baseline_data:
        logging.error("No files were hashed. Baseline not created.")
        return

    final_baseline = {
        "metadata": {"creation_date": datetime.now().isoformat(), "hash_algorithm": algorithm},
        "hashes": baseline_data
    }
    with open(baseline_file, 'w') as f:
        json.dump(final_baseline, f, indent=4)
    logging.info(f"--- Baseline created successfully at '{baseline_file}' ---")

def run_scan(config):
    """Scans the system and sends email alerts on changes."""
    logging.info("--- Running Integrity Scan ---")
    baseline_file = config['FIM']['baseline_file']
    if not os.path.exists(baseline_file):
        logging.error(f"Baseline file '{baseline_file}' not found. Please run 'baseline' command first.")
        return

    with open(baseline_file, 'r') as f:
        baseline_json = json.load(f)
    baseline_hashes = baseline_json.get("hashes", {})
    algorithm = baseline_json.get("metadata", {}).get("hash_algorithm")

    paths_to_monitor = get_monitored_paths(config)
    current_hashes = generate_hashes_from_paths(paths_to_monitor, algorithm)

    baseline_files = set(baseline_hashes.keys())
    current_files = set(current_hashes.keys())

    added_files = current_files - baseline_files
    deleted_files = baseline_files - current_files
    modified_files = {fp for fp in baseline_files & current_files if baseline_hashes[fp] != current_hashes[fp]}

    if not any([added_files, deleted_files, modified_files]):
        logging.info("System integrity check passed. No changes detected.")
    else:
        logging.warning("!!! System integrity check FAILED! Changes detected. !!!")
        alert_subject = f"FIM ALERT on {os.environ.get('COMPUTERNAME', 'this host')}"
        alert_body = "The following file integrity changes were detected:\n\n"
        if modified_files:
            alert_body += "--- MODIFIED FILES ---\n" + "\n".join(sorted(modified_files)) + "\n\n"
        if added_files:
            alert_body += "--- ADDED FILES ---\n" + "\n".join(sorted(added_files)) + "\n\n"
        if deleted_files:
            alert_body += "--- DELETED FILES ---\n" + "\n".join(sorted(deleted_files)) + "\n\n"

        # Directly call the email alert function
        send_email_alert(config, alert_subject, alert_body)

    logging.info("--- Scan Complete ---")

# --- COMMAND-LINE INTERFACE ---

if __name__ == "__main__":
    try:
        config = load_config()
        setup_logging(config['FIM']['log_file'])
        parser = argparse.ArgumentParser(description="A Windows File Integrity Monitoring (FIM) tool with email alerts.")
        subparsers = parser.add_subparsers(dest='command', required=True)
        subparsers.add_parser('baseline', help='Create a new integrity baseline.')
        subparsers.add_parser('scan', help='Scan files against the baseline.')
        args = parser.parse_args()
        if args.command == 'baseline':
            create_baseline(config)
        elif args.command == 'scan':
            run_scan(config)
    except Exception as e:
        logging.critical(f"A critical error occurred: {e}", exc_info=True)