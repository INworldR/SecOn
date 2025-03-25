#!/Users/marc/miniconda3/envs/SecOn/bin/python

import os
import time
import argparse
import requests
import subprocess
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from .env
load_dotenv("../.env")

# Get credentials from environment
ELASTIC_URL = os.getenv("ELASTIC_URL")
USERNAME = os.getenv("ELASTIC_USER")
PASSWORD = os.getenv("ELASTIC_PASSWORD")

def open_ssh_tunnel():
    """
    Open an SSH tunnel in the background.
    Returns the subprocess object for later termination.
    """
    cmd = [
        "ssh", "-L", "9200:localhost:9200", "-N", "-T", "secon"
    ]
    return subprocess.Popen(cmd)

def get_logs(hostname: str, limit: int = 20, index: str = "logs-*", debug: bool = False, dry_run: bool = False):
    """
    Fetch the most recent log entries for a specific host from Elasticsearch.

    Args:
        hostname (str): The name of the host to filter logs by.
        limit (int): Number of log entries to retrieve.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don’t send request.

    Returns:
        list[dict]: A list of log entries as dictionaries.
    """
    url = ELASTIC_URL.replace("logs-*", index)

    query = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "match": {
                "host.name": hostname
            }
        }
    }

    if dry_run or debug:
        print(f"Query URL: {url}")
        print(f"Query Body:\n{query}")

    if dry_run:
        return []

    try:
        response = requests.post(
            url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers={"Content-Type": "application/json"},
            json=query,
            verify=False
        )
        response.raise_for_status()

        if debug:
            print("Raw response:", response.text)

        hits = response.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return []

def parse_args():
    """
    Parse command-line arguments and show help if none provided.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="Query recent Elasticsearch logs for a specific host"
    )
    parser.add_argument("--hostname", type=str, default="cto", help="Hostname to filter logs by")
    parser.add_argument("--limit", type=int, default=20, help="Number of log entries to retrieve")
    parser.add_argument("--index", type=str, default="logs-*", help="Index pattern to search (e.g. logs-* or filebeat-*)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--dry-run", action="store_true", help="Show the query but don't send the request")

    # Show help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    print("[+] Opening SSH tunnel to tsecon...")
    tunnel = open_ssh_tunnel()
    time.sleep(1.5)  # Give tunnel time to initialize

    try:
        logs = get_logs(
            hostname=args.hostname,
            limit=args.limit,
            index=args.index,
            debug=args.debug,
            dry_run=args.dry_run
        )
        if logs:
            for log in logs:
                timestamp = log.get("@timestamp", "N/A")
                message = log.get("message", str(log)[:100])
                print(f"{timestamp} - {message}")
        elif not args.dry_run:
            print("[!] No logs found or failed to retrieve logs.")
    finally:
        print("[+] Closing SSH tunnel...")
        tunnel.terminate()
        tunnel.wait()

