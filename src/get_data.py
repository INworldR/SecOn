#!/usr/bin/env python

import os
import time
import sys
import re
import json
import argparse
import requests
import subprocess
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
# Optional import for YAML output
try:
    import yaml
except ImportError:
    pass
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

def build_query(hostname=None, hours=None, program=None, priority=None, 
                pattern=None, limit=20, debug=False):
    """
    Build Elasticsearch query based on provided filters.
    
    Args:
        hostname (str): Host to filter logs by
        hours (int): Number of hours to look back
        program (str): Program/service name to filter by
        priority (str): Syslog priority to filter by
        pattern (str): Regex pattern to search in message field
        limit (int): Number of results to return
        debug (bool): Enable verbose output
        
    Returns:
        dict: Elasticsearch query
    """
    # Start with a match_all query
    query = {
        "bool": {
            "must": []
        }
    }
    
    # Add hostname filter
    if hostname:
        query["bool"]["must"].append({"match": {"host.name": hostname}})
    
    # Add time range filter
    if hours:
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{hours}h",
                    "lte": "now"
                }
            }
        }
        query["bool"]["must"].append(time_filter)
    
    # Add program/service filter
    if program:
        program_filter = {"match": {"program": program}}
        query["bool"]["must"].append(program_filter)
    
    # Add priority filter
    if priority:
        priority_filter = {"match": {"syslog.priority": priority}}
        query["bool"]["must"].append(priority_filter)
    
    # Add regex pattern search on message field
    if pattern:
        pattern_filter = {
            "regexp": {
                "message": {
                    "value": pattern
                }
            }
        }
        query["bool"]["must"].append(pattern_filter)
    
    # If no filters were added, use match_all
    if not query["bool"]["must"]:
        query = {"match_all": {}}
    
    # Build the full request body
    request_body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": query
    }
    
    if debug:
        print(f"Query body: {json.dumps(request_body, indent=2)}")
        
    return request_body

def get_logs(hostname=None, hours=None, program=None, priority=None, 
             pattern=None, limit=20, index="logs-*", debug=False, dry_run=False):
    """
    Fetch filtered log entries from Elasticsearch.

    Args:
        hostname (str): The name of the host to filter logs by.
        hours (int): Number of hours to look back in logs.
        program (str): Filter logs by program/service name.
        priority (str): Filter logs by syslog priority.
        pattern (str): Regex pattern to search in message field.
        limit (int): Number of log entries to retrieve.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don't send request.

    Returns:
        list[dict]: A list of log entries as dictionaries.
    """
    url = ELASTIC_URL.replace("logs-*", index)
    
    # Build the query with all filters
    query = build_query(
        hostname=hostname,
        hours=hours,
        program=program,
        priority=priority,
        pattern=pattern,
        limit=limit,
        debug=debug
    )

    if dry_run:
        print(f"Query URL: {url}")
        print(f"Query Body:\n{json.dumps(query, indent=2)}")
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
            print("Raw response:", response.text[:1000])  # Limit output size

        hits = response.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return []

def format_logs(logs, format_type="default"):
    """
    Format log entries for display.
    
    Args:
        logs (list): List of log entry dictionaries
        format_type (str): Display format type (default, json, yaml)
        
    Returns:
        list: Formatted log strings
    """
    formatted = []
    
    if format_type == "json":
        return [json.dumps(log, indent=2) for log in logs]
    elif format_type == "yaml":
        try:
            import yaml
            return [yaml.dump(log, default_flow_style=False) for log in logs]
        except ImportError:
            print("[!] PyYAML is not installed. Falling back to default format.")
            format_type = "default"
    
    # Default format - preserve original format
    for log in logs:
        timestamp = log.get("@timestamp", "N/A")
        message = log.get("message", str(log)[:100])
        formatted.append(f"{timestamp} - {message}")
            
    return formatted

def parse_args():
    """
    Parse command-line arguments and show help if none provided.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Query Elasticsearch logs with flexible filtering options"
    )
    
    # Basic filters
    parser.add_argument("--hostname", type=str, help="Hostname to filter logs by")
    parser.add_argument("--hours", type=int, help="Get logs from the last N hours")
    parser.add_argument("--program", type=str, help="Filter by program/service name")
    parser.add_argument("--priority", type=str, help="Filter by syslog priority")
    parser.add_argument("--pattern", type=str, help="Regex pattern to search in message field")
    
    # Output control
    parser.add_argument("--limit", type=int, default=20, help="Number of log entries to retrieve")
    parser.add_argument("--index", type=str, default="logs-*", help="Index pattern to search")
    parser.add_argument("--format", choices=["default", "json", "yaml"], default="default", help="Output format")
    
    # Debug options
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--dry-run", action="store_true", help="Show the query but don't send the request")
    
    # Show help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Validate that at least one filter is specified
    if not any([args.hostname, args.hours, args.program, args.priority, args.pattern]):
        parser.error("At least one filter (--hostname, --hours, --program, --priority, or --pattern) must be specified")
    
    return args

if __name__ == "__main__":
    args = parse_args()

    print("[+] Opening SSH tunnel to secon...")
    tunnel = open_ssh_tunnel()
    time.sleep(1.5)  # Give tunnel time to initialize

    try:
        logs = get_logs(
            hostname=args.hostname,
            hours=args.hours,
            program=args.program,
            priority=args.priority,
            pattern=args.pattern,
            limit=args.limit,
            index=args.index,
            debug=args.debug,
            dry_run=args.dry_run
        )
        
        if logs:
            formatted_logs = format_logs(logs, args.format)
            for log_entry in formatted_logs:
                print(log_entry)
        elif not args.dry_run:
            print("[!] No logs found or failed to retrieve logs.")
    finally:
        print("[+] Closing SSH tunnel...")
        tunnel.terminate()
        tunnel.wait()
