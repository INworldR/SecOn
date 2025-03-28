#!/usr/bin/env python

import os
import time
import sys
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

def oql_to_elasticsearch(oql_query, hours=None, debug=False):
    """
    Convert Onion Query Language (OQL) directly to Elasticsearch DSL.
    This implementation preserves the OQL structure while adding time filters if needed.
    
    Args:
        oql_query (str): Onion Query Language query string
        hours (int): Optional hours filter to add to query
        debug (bool): Enable verbose output
        
    Returns:
        dict: Elasticsearch query body
    """
    if debug:
        print(f"Processing OQL query: {oql_query}")
    
    # Split the query into parts (query | pipeline)
    parts = oql_query.split('|', 1)
    query_part = parts[0].strip()
    pipeline_part = parts[1].strip() if len(parts) > 1 else None
    
    # Direct translation of OQL to Elasticsearch
    # Start with an empty query
    query_body = {"bool": {"must": []}}
    
    # Add each term from the query part
    query_terms = query_part.split()
    for term in query_terms:
        if ':' in term:
            field, value = term.split(':', 1)
            
            # Handle wildcards
            if '*' in value:
                query_body["bool"]["must"].append({
                    "wildcard": {
                        field: value
                    }
                })
            else:
                query_body["bool"]["must"].append({
                    "match": {
                        field: value
                    }
                })
    
    # Add time filter if hours parameter is provided
    if hours:
        query_body["bool"]["must"].append({
            "range": {
                "@timestamp": {
                    "gte": f"now-{hours}h",
                    "lte": "now"
                }
            }
        })
    
    # If no filters were added, use match_all
    if not query_body["bool"]["must"]:
        query_body = {"match_all": {}}
    
    # Build request body
    request_body = {
        "query": query_body
    }
    
    # Parse pipeline part (if present)
    if pipeline_part:
        # Handle groupby
        if pipeline_part.startswith('groupby'):
            group_fields = pipeline_part[8:].strip().split(',')
            aggs = {
                "groupby": {
                    "terms": {
                        "field": group_fields[0].strip(),
                        "size": 10
                    }
                }
            }
            
            # Handle nested groupby
            if len(group_fields) > 1:
                current_agg = aggs["groupby"]
                for field in group_fields[1:]:
                    current_agg["aggs"] = {
                        "groupby": {
                            "terms": {
                                "field": field.strip(),
                                "size": 10
                            }
                        }
                    }
                    current_agg = current_agg["aggs"]["groupby"]
            
            request_body["size"] = 0  # No need for individual docs with aggregations
            request_body["aggs"] = aggs
        else:
            # Add support for other pipeline operations here
            pass
    else:
        # For non-aggregation queries, include size and sort
        request_body["size"] = 100  # Default limit
        request_body["sort"] = [{"@timestamp": "desc"}]
    
    if debug:
        print(f"Translated query: {json.dumps(request_body, indent=2)}")
        
    return request_body

def get_logs(oql, hours=None, limit=100, index="logs-*", debug=False, dry_run=False):
    """
    Fetch logs from Elasticsearch using OQL.

    Args:
        oql (str): Onion Query Language query string.
        hours (int): Optional time filter (hours back).
        limit (int): Number of log entries to retrieve.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don't send request.

    Returns:
        list[dict] or dict: A list of log entries or aggregation results.
    """
    url = ELASTIC_URL.replace("logs-*", index)
    
    # Convert OQL directly to Elasticsearch DSL
    query = oql_to_elasticsearch(oql, hours, debug)
    
    # Override size if hours is specified (get all matching logs)
    if hours is not None:
        query["size"] = 10000  # Set to a high value (Elasticsearch has a default max of 10000)
    # Override size if set in arguments and not an aggregation query
    elif "aggs" not in query and limit:
        query["size"] = limit

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

        result = response.json()
        
        # Check if this is an aggregation query response
        if "aggregations" in result:
            return result  # Return the full response for aggregation queries
        
        # Otherwise, just return the hits
        hits = result.get("hits", {}).get("hits", [])
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

def export_logs(logs, filename, format_type="default"):
    """
    Export log entries to a file.
    
    Args:
        logs (list or dict): Log entries or aggregation results
        filename (str): Target filename to export to
        format_type (str): Export format type (default, json, yaml)
        
    Returns:
        bool: Success status
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            if isinstance(logs, dict) and "aggregations" in logs:
                # For aggregation results
                if format_type == "json":
                    json.dump(logs["aggregations"], f, indent=2)
                elif format_type == "yaml":
                    try:
                        import yaml
                        yaml.dump(logs["aggregations"], f, default_flow_style=False)
                    except ImportError:
                        json.dump(logs["aggregations"], f, indent=2)
                else:
                    # Print a simplified version of the aggregations
                    if "groupby" in logs["aggregations"]:
                        buckets = logs["aggregations"]["groupby"]["buckets"]
                        for bucket in buckets:
                            f.write(f"{bucket['key']}: {bucket['doc_count']} documents\n")
                            # Handle nested aggregations if they exist
                            if "groupby" in bucket:
                                nested_buckets = bucket["groupby"]["buckets"]
                                for nested_bucket in nested_buckets:
                                    f.write(f"  {nested_bucket['key']}: {nested_bucket['doc_count']} documents\n")
            else:
                # For regular log results
                formatted_logs = format_logs(logs, format_type)
                for log_entry in formatted_logs:
                    f.write(f"{log_entry}\n")
                    
        print(f"[+] Successfully exported logs to {filename}")
        return True
    except Exception as e:
        print(f"[!] Error exporting logs: {e}")
        return False

def parse_args():
    """
    Parse command-line arguments and show help if none provided.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Query Elasticsearch logs using Onion Query Language (OQL)"
    )
    
    # Required OQL parameter
    parser.add_argument("--oql", type=str, required=True, 
                        help="Onion Query Language query string")
    
    # Optional parameters
    parser.add_argument("--hours", type=int, 
                        help="Get logs from the last N hours")
    parser.add_argument("--limit", type=int, default=100, 
                        help="Number of log entries to retrieve (for non-aggregation queries)")
    parser.add_argument("--index", type=str, default="logs-*", 
                        help="Index pattern to search")
    parser.add_argument("--format", choices=["default", "json", "yaml"], 
                        default="default", help="Output format")
    parser.add_argument("--export", type=str,
                       help="Export results to the specified file")
    
    # Debug options
    parser.add_argument("--debug", action="store_true", 
                        help="Enable verbose debug output")
    parser.add_argument("--dry-run", action="store_true", 
                        help="Show the query but don't send the request")
    
    # Show help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    print("[+] Opening SSH tunnel to secon...")
    tunnel = open_ssh_tunnel()
    time.sleep(1.5)  # Give tunnel time to initialize

    try:
        logs = get_logs(
            oql=args.oql,
            hours=args.hours,
            limit=args.limit,
            index=args.index,
            debug=args.debug,
            dry_run=args.dry_run
        )
        
        if logs:
            # Handle export and display
            if args.export and not args.dry_run:
                export_logs(logs, args.export, args.format)
                print(f"[+] Exported {len(logs) if isinstance(logs, list) else 'aggregated'} logs to {args.export}")
            # Display to console only if not exporting and not a dry run
            elif not args.dry_run:
                # Check if we have aggregation results (from OQL with groupby)
                if isinstance(logs, dict) and "aggregations" in logs:
                    # Pretty print aggregation results
                    if args.format == "json":
                        print(json.dumps(logs["aggregations"], indent=2))
                    elif args.format == "yaml":
                        if 'yaml' in sys.modules:
                            print(yaml.dump(logs["aggregations"], default_flow_style=False))
                        else:
                            print(json.dumps(logs["aggregations"], indent=2))
                            print("\n[!] PyYAML not installed. Falling back to JSON format.")
                    else:
                        # Print a simplified version of the aggregations
                        print("\nAggregation Results:")
                        if "groupby" in logs["aggregations"]:
                            buckets = logs["aggregations"]["groupby"]["buckets"]
                            for bucket in buckets:
                                print(f"{bucket['key']}: {bucket['doc_count']} documents")
                                # Handle nested aggregations if they exist
                                if "groupby" in bucket:
                                    nested_buckets = bucket["groupby"]["buckets"]
                                    for nested_bucket in nested_buckets:
                                        print(f"  {nested_bucket['key']}: {nested_bucket['doc_count']} documents")
                else:
                    # Regular log results
                    formatted_logs = format_logs(logs, args.format)
                    for log_entry in formatted_logs:
                        print(log_entry)
        elif not args.dry_run:
            print("[!] No logs found or failed to retrieve logs.")
    finally:
        print("[+] Closing SSH tunnel...")
        tunnel.terminate()
        tunnel.wait()
