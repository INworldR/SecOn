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

def parse_oql(oql_query, debug=False):
    """
    Parse Onion Query Language query and convert it to Elasticsearch DSL.
    This is a simple implementation that supports basic OQL syntax.
    
    Args:
        oql_query (str): Onion Query Language query string
        debug (bool): Enable verbose output
        
    Returns:
        dict: Elasticsearch query parts (query, aggs)
    """
    if debug:
        print(f"Parsing OQL query: {oql_query}")
    
    # Split the query into parts (query | pipeline)
    parts = oql_query.split('|', 1)
    query_part = parts[0].strip()
    pipeline_part = parts[1].strip() if len(parts) > 1 else None
    
    # Parse the query part
    query_terms = query_part.split()
    must_clauses = []
    
    for term in query_terms:
        if ':' in term:
            field, value = term.split(':', 1)
            
            # Handle wildcards
            if '*' in value:
                must_clauses.append({
                    "wildcard": {
                        field: value
                    }
                })
            else:
                must_clauses.append({
                    "match": {
                        field: value
                    }
                })
    
    # Parse pipeline part (if present)
    aggs = {}
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
    
    # Build the query
    if must_clauses:
        query = {
            "bool": {
                "must": must_clauses
            }
        }
    else:
        query = {"match_all": {}}
    
    if debug:
        print(f"Parsed query: {json.dumps(query, indent=2)}")
        if aggs:
            print(f"Parsed aggregations: {json.dumps(aggs, indent=2)}")
    
    return {"query": query, "aggs": aggs}

def build_query(hostname=None, hours=None, program=None, priority=None, 
                pattern=None, oql=None, limit=20, debug=False):
    """
    Build Elasticsearch query based on provided filters.
    
    Args:
        hostname (str): Host to filter logs by
        hours (int): Number of hours to look back
        program (str): Program/service name to filter by
        priority (str): Syslog priority to filter by
        pattern (str): Regex pattern to search in message field
        oql (str): Onion Query Language query string
        limit (int): Number of results to return
        debug (bool): Enable verbose output
        
    Returns:
        dict: Elasticsearch query
    """
    # Check if OQL is provided
    if oql:
        # Parse OQL and get query and aggregations
        oql_parts = parse_oql(oql, debug)
        query = oql_parts["query"]
        aggs = oql_parts["aggs"]
        
        # Start with the query from OQL
        request_body = {
            "size": 0 if aggs else limit,  # If aggregations, don't need individual docs
            "sort": [{"@timestamp": "desc"}],
            "query": query
        }
        
        # Add aggregations if present
        if aggs:
            request_body["aggs"] = aggs
        
        if debug:
            print(f"OQL query body: {json.dumps(request_body, indent=2)}")
            
        return request_body
    
    # Start with a match_all query for standard filters
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
             pattern=None, oql=None, limit=20, index="logs-*", debug=False, dry_run=False):
    """
    Fetch filtered log entries from Elasticsearch.

    Args:
        hostname (str): The name of the host to filter logs by.
        hours (int): Number of hours to look back in logs.
        program (str): Filter logs by program/service name.
        priority (str): Filter logs by syslog priority.
        pattern (str): Regex pattern to search in message field.
        oql (str): Onion Query Language query string.
        limit (int): Number of log entries to retrieve.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don't send request.

    Returns:
        list[dict] or dict: A list of log entries or aggregation results.
    """
    url = ELASTIC_URL.replace("logs-*", index)
    
    # Build the query with all filters
    query = build_query(
        hostname=hostname,
        hours=hours,
        program=program,
        priority=priority,
        pattern=pattern,
        oql=oql,
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
    parser.add_argument("--oql", type=str, help="Onion Query Language query string")
    
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
    if not any([args.hostname, args.hours, args.program, args.priority, args.pattern, args.oql]):
        parser.error("At least one filter (--hostname, --hours, --program, --priority, --pattern, or --oql) must be specified")
    
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
            oql=args.oql,
            limit=args.limit,
            index=args.index,
            debug=args.debug,
            dry_run=args.dry_run
        )
        
        if logs:
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
