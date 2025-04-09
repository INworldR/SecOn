#!/usr/bin/env python
"""
get_web_data.py - Extract and process web server logs from SecurityOnion

This script is designed to retrieve Apache2 and PHP logs from SecurityOnion's
Elasticsearch database. It uses specific patterns to correctly identify web logs.

Usage:
    python get_web_data.py [--options]
"""

import os
import time
import sys
import json
import argparse
import requests
import subprocess
import re
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import signal
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

def parse_term(term, debug=False):
    """Helper function to parse a single OQL term into an Elasticsearch query clause."""
    if debug:
        print(f"Parsing term: {term}")
        
    if term.startswith("(") and term.endswith(")"):
        # Handle parenthesized expressions (just strip the parentheses for now)
        return parse_term(term[1:-1], debug)
        
    # Handle AND/OR operators
    if " AND " in term:
        and_parts = term.split(" AND ")
        and_clauses = [parse_term(part, debug) for part in and_parts]
        return {"bool": {"must": and_clauses}}
    
    if " OR " in term:
        or_parts = term.split(" OR ")
        or_clauses = [parse_term(part, debug) for part in or_parts]
        return {"bool": {"should": or_clauses}}
    
    # Handle field:value expressions
    if ":" in term:
        field, value = term.split(":", 1)
        field = field.strip()
        value = value.strip()
        
        # Special handling for @timestamp
        if field == "@timestamp":
            # Handle date range expressions (e.g., @timestamp:>=2025-03-27)
            if value.startswith(">="):
                return {"range": {field: {"gte": value[2:]}}}
            elif value.startswith(">"):
                return {"range": {field: {"gt": value[1:]}}}
            elif value.startswith("<="):
                return {"range": {field: {"lte": value[2:]}}}
            elif value.startswith("<"):
                return {"range": {field: {"lt": value[1:]}}}
            
            # Handle date range with brackets (e.g., @timestamp:[2025-03-27 TO 2025-03-28])
            elif value.startswith("[") and " TO " in value and value.endswith("]"):
                range_parts = value[1:-1].split(" TO ")
                if len(range_parts) == 2:
                    start_date = range_parts[0].strip()
                    end_date = range_parts[1].strip()
                    
                    # If the dates don't include time, assume full day
                    if "T" not in start_date and len(start_date) <= 10:
                        start_date = f"{start_date}T00:00:00.000Z"
                    if "T" not in end_date and len(end_date) <= 10:
                        end_date = f"{end_date}T23:59:59.999Z"
                        
                    if debug:
                        print(f"Parsed date range: {start_date} to {end_date}")
                        
                    return {"range": {field: {"gte": start_date, "lte": end_date}}}
            
            # For simple @timestamp matching, convert to a full-day range
            if not any(op in value for op in ["*", ">", "<", "[", "TO"]):
                # Assume this is a date in format YYYY-MM-DD
                date_str = value.strip()
                if "T" not in date_str and len(date_str) <= 10:  # Just a date without time
                    return {"range": {
                        field: {
                            "gte": f"{date_str}T00:00:00.000Z",
                            "lt": f"{date_str}T23:59:59.999Z"
                        }
                    }}
        
        # Handle wildcards and regular matches
        if "*" in value:
            return {"wildcard": {field: value}}
        else:
            return {"match": {field: value}}
    
    # Default to a simple match query
    return {"match_all": {}}

def oql_to_elasticsearch(oql_query, hours=None, debug=False):
    """
    Convert Onion Query Language (OQL) directly to Elasticsearch DSL.
    This implementation preserves the OQL structure while adding time filters if needed.
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
    
    # Parse complex OQL queries (e.g., with AND/OR operators)
    if " AND " in query_part or " OR " in query_part:
        query_clause = parse_term(query_part, debug)
        # Replace the entire query_body with the parsed complex query
        query_body = query_clause
    else:
        # Process simple space-separated terms (implicit AND)
        query_terms = query_part.split()
        for term in query_terms:
            if ":" in term:
                clause = parse_term(term, debug)
                query_body["bool"]["must"].append(clause)
    
    # Add time filter if hours parameter is provided
    if hours:
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{hours}h",
                    "lte": "now"
                }
            }
        }
        
        # Add to the appropriate part of the query
        if "bool" in query_body:
            if "must" in query_body["bool"]:
                query_body["bool"]["must"].append(time_filter)
            else:
                query_body["bool"]["must"] = [time_filter]
        else:
            # If it's not a bool query already, wrap it
            original_query = query_body
            query_body = {
                "bool": {
                    "must": [original_query, time_filter]
                }
            }
    
    # If no filters were added, use match_all
    if "bool" in query_body and not query_body["bool"].get("must", []):
        query_body = {"match_all": {}}
    
    if debug:
        print(f"Translated query: {json.dumps(query_body, indent=2)}")
        
    return query_body

def build_web_log_query(apache=True, php=True, oql="", debug=False):
    """
    Build a refined query specifically for web logs.
    
    Args:
        apache: Include Apache logs
        php: Include PHP logs
        oql: Additional OQL query to include
        debug: Enable debug output
        
    Returns:
        dict: Elasticsearch query object
    """
    # Build a more precise web log query
    should_clauses = []
    
    if apache:
        # More precise matching for Apache logs - look for specific patterns
        should_clauses.extend([
            {"match_phrase": {"message": "apache"}},
            {"match_phrase": {"message": "httpd"}},
            {"match_phrase": {"process.name": "apache2"}},
            {"match_phrase": {"process.name": "httpd"}},
            # Common Apache log format pattern
            {"regexp": {"message": "\\d+\\.\\d+\\.\\d+\\.\\d+ - - \\[.*\\] \"(GET|POST|PUT|DELETE|HEAD|OPTIONS)"}},
            # Look for HTTP status codes
            {"regexp": {"message": "HTTP/\\d.\\d\" \\d{3}"}}
        ])
    
    if php:
        # More precise matching for PHP logs
        should_clauses.extend([
            {"match_phrase": {"message": "PHP"}},
            {"match_phrase": {"process.name": "php"}},
            {"match_phrase": {"process.name": "php-fpm"}},
            # PHP error patterns
            {"regexp": {"message": "\\[.*\\] PHP (Warning|Notice|Fatal error|Parse error)"}},
            {"regexp": {"message": "PHP Stack trace:"}}
        ])
    
    # Create the web logs query
    web_query = {
        "bool": {
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    # If there's an additional OQL query, combine it with the web query
    if oql:
        # Convert the OQL to an Elasticsearch query object
        oql_query = oql_to_elasticsearch(oql, debug=debug)
        
        # Combine the queries with AND
        combined_query = {
            "bool": {
                "must": [
                    web_query,
                    oql_query
                ]
            }
        }
        return combined_query
    else:
        return web_query

def get_logs(oql="", hours=None, limit=100, index="logs-*", apache=True, php=True, debug=False, dry_run=False):
    """
    Fetch web logs from Elasticsearch.

    Args:
        oql: Onion Query Language query string (optional).
        hours: Optional time filter (hours back).
        limit: Number of log entries to retrieve.
        index: Index pattern to search within.
        apache: Include Apache logs.
        php: Include PHP logs.
        debug: Enable verbose debug output.
        dry_run: If True, show query but don't send request.

    Returns:
        list[dict] or dict: A list of log entries or aggregation results.
    """
    url = ELASTIC_URL.replace("logs-*", index)
    
    # Build a specialized web log query
    query = build_web_log_query(apache, php, oql, debug)
    
    # Add time filter if hours parameter is provided
    if hours:
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{hours}h",
                    "lte": "now"
                }
            }
        }
        
        # Add to the appropriate part of the query
        if "bool" in query:
            if "must" in query["bool"]:
                query["bool"]["must"].append(time_filter)
            else:
                query["bool"]["must"] = [time_filter]
        else:
            # If it's not a bool query already, wrap it
            query = {
                "bool": {
                    "must": [query, time_filter]
                }
            }
    
    # Check if this is an aggregation query
    parts = oql.split('|', 1) if oql else ["", ""]
    pipeline_part = parts[1].strip() if len(parts) > 1 else None
    
    # For aggregation queries, build the full request body
    if pipeline_part and pipeline_part.startswith('groupby'):
        request_body = {
            "query": query,
            "size": 0  # No need for individual docs with aggregations
        }
        
        # Parse the groupby part
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
        
        request_body["aggs"] = aggs
    else:
        # For non-aggregation queries, create a simpler query
        request_body = {
            "query": query,
            "size": min(10000, limit) if limit else 10000,  # Respect the Elasticsearch limit
            "sort": [{"@timestamp": "desc"}]
        }

    if dry_run:
        print(f"Query URL: {url}")
        print(f"Query Body:\n{json.dumps(request_body, indent=2)}")
        return []

    try:
        response = requests.post(
            url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers={"Content-Type": "application/json"},
            json=request_body,
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
        
        # Filter out any false positives that don't have web log characteristics
        filtered_hits = []
        for hit in hits:
            source = hit["_source"]
            message = source.get("message", "").lower()
            # Only include genuine web logs
            if (
                "apache" in message or
                "httpd" in message or
                "php" in message or
                "http/1." in message or
                "get /" in message or
                "post /" in message or
                "php warning" in message or
                "php error" in message or
                ("process" in source and source["process"].get("name") in ["apache2", "httpd", "php", "php-fpm"])
            ):
                filtered_hits.append(source)
                
        if debug and len(hits) != len(filtered_hits):
            print(f"[!] Filtered out {len(hits) - len(filtered_hits)} false positive matches")
            
        return filtered_hits

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return []

def get_all_logs_with_search_after(oql="", hours=None, batch_size=1000, index="logs-*", apache=True, php=True, debug=False, dry_run=False, 
                   progress_interval=5, max_results=None):
    """
    Fetch all web logs from Elasticsearch using search_after pagination.
    """
    # Build the web log query
    query = build_web_log_query(apache, php, oql, debug)
    
    # Add time filter if hours parameter is provided
    if hours:
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{hours}h",
                    "lte": "now"
                }
            }
        }
        
        # Add to the appropriate part of the query
        if "bool" in query:
            if "must" in query["bool"]:
                query["bool"]["must"].append(time_filter)
            else:
                query["bool"]["must"] = [time_filter]
        else:
            # If it's not a bool query already, wrap it
            query = {
                "bool": {
                    "must": [query, time_filter]
                }
            }
    
    url = ELASTIC_URL.replace("logs-*", index)
    
    if dry_run:
        print(f"Query URL: {url}")
        print(f"Query (search_after pagination will be used):\n{json.dumps(query, indent=2)}")
        return []
    
    try:
        all_results = []
        search_after = None
        last_progress_time = time.time()
        total_retrieved = 0
        batch_num = 1
        
        print(f"[+] Starting web log extraction with batch size {batch_size} using search_after pagination...")
        
        while True:
            # Prepare the request body
            request_body = {
                "query": query,
                "size": batch_size,
                "sort": [
                    {"@timestamp": "desc"},
                    {"_id": "asc"}  # Secondary sort for stability
                ]
            }
            
            # Add search_after if we have it from a previous batch
            if search_after:
                request_body["search_after"] = search_after
            
            # Send the request
            response = requests.post(
                url,
                auth=HTTPBasicAuth(USERNAME, PASSWORD),
                headers={"Content-Type": "application/json"},
                json=request_body,
                verify=False
            )
            response.raise_for_status()
            
            result = response.json()
            
            # Extract hits
            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break  # No more results
                
            # Filter out false positives
            filtered_hits = []
            for hit in hits:
                source = hit["_source"]
                message = source.get("message", "").lower()
                # Only include genuine web logs
                if (
                    "apache" in message or
                    "httpd" in message or
                    "php" in message or
                    "http/1." in message or
                    "get /" in message or
                    "post /" in message or
                    "php warning" in message or
                    "php error" in message or
                    ("process" in source and source["process"].get("name") in ["apache2", "httpd", "php", "php-fpm"])
                ):
                    filtered_hits.append(source)
            
            if debug and len(hits) != len(filtered_hits):
                print(f"[!] Filtered out {len(hits) - len(filtered_hits)} false positive matches in batch {batch_num}")
                
            # Extract documents
            all_results.extend(filtered_hits)
            total_retrieved += len(filtered_hits)
            
            # If we got no valid results in this batch but there were hits, continue to next batch
            if not filtered_hits and hits:
                # Prepare for next iteration
                last_hit = hits[-1]
                search_after = last_hit["sort"]
                batch_num += 1
                continue
                
            # Update progress periodically
            current_time = time.time()
            if current_time - last_progress_time >= progress_interval:
                print(f"[+] Retrieved {total_retrieved} web log entries so far (batch {batch_num})...")
                last_progress_time = current_time
                
            # Prepare for next iteration
            if hits:
                last_hit = hits[-1]
                search_after = last_hit["sort"]
                batch_num += 1
            else:
                break
            
            # Check if we've reached the maximum requested number of results
            if max_results and total_retrieved >= max_results:
                print(f"[+] Reached maximum requested results: {max_results}")
                break
        
        print(f"[+] Extraction complete. Retrieved {total_retrieved} web log entries in {batch_num-1} batches.")
        return all_results
        
    except Exception as e:
        print(f"[!] Error during extraction: {e}")
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
                if format_type == "json":
                    # Use a more efficient approach for large datasets
                    f.write("[\n")
                    for i, log_entry in enumerate(logs):
                        if i > 0:
                            f.write(",\n")
                        f.write(json.dumps(log_entry, indent=2))
                    f.write("\n]")
                elif format_type == "yaml":
                    try:
                        import yaml
                        yaml.dump(logs, f, default_flow_style=False)
                    except ImportError:
                        # Fall back to JSON if YAML is not available
                        json.dump(logs, f, indent=2)
                else:
                    # Default format - one log entry per line
                    formatted_logs = format_logs(logs, format_type)
                    for log_entry in formatted_logs:
                        f.write(f"{log_entry}\n")
                    
        print(f"[+] Successfully exported logs to {filename}")
        return True
    except Exception as e:
        print(f"[!] Error exporting logs: {e}")
        return False

def open_ssh_tunnel():
    """
    Open an SSH tunnel in the background.
    Returns the subprocess object for later termination.
    """
    cmd = [
        "ssh", "-L", "9200:localhost:9200", "-N", "-T", "secon"
    ]
    return subprocess.Popen(cmd)

def handle_sigint(signum, frame, tunnel=None):
    """Handle keyboard interrupt by cleaning up resources."""
    print("\n[!] Interrupted by user. Cleaning up...")
    if tunnel:
        print("[+] Closing SSH tunnel...")
        tunnel.terminate()
        tunnel.wait()
    sys.exit(1)

def parse_args():
    """Parse command-line arguments and show help if none provided."""
    parser = argparse.ArgumentParser(
        description="Extract and analyze web server logs from SecurityOnion"
    )
    
    # Basic parameters
    parser.add_argument("--oql", type=str, default="",
                       help="Onion Query Language query string (optional)")
    parser.add_argument("--hours", type=int, default=24,
                       help="Get logs from the last N hours (default: 24)")
    parser.add_argument("--limit", type=int, default=100,
                       help="Number of log entries to retrieve (for non-extraction queries)")
    parser.add_argument("--index", type=str, default="logs-*",
                       help="Index pattern to search")
    
    # Date range options
    parser.add_argument("--from-date", type=str,
                       help="Start date (format: YYYY-MM-DD)")
    parser.add_argument("--to-date", type=str,
                       help="End date (format: YYYY-MM-DD)")
    
    # Web log options
    parser.add_argument("--apache", action="store_true", default=True,
                       help="Include Apache2 logs (default: True)")
    parser.add_argument("--php", action="store_true", default=True,
                       help="Include PHP logs (default: True)")
    parser.add_argument("--no-apache", action="store_true",
                       help="Exclude Apache2 logs")
    parser.add_argument("--no-php", action="store_true",
                       help="Exclude PHP logs")
    
    # Output options
    parser.add_argument("--format", choices=["default", "json", "yaml"],
                        default="json", help="Output format")
    parser.add_argument("--export", type=str,
                       help="Export results to the specified file")
    
    # Extraction options
    parser.add_argument("--full-extract", action="store_true",
                       help="Extract all matching documents using pagination")
    parser.add_argument("--batch-size", type=int, default=1000,
                       help="Number of documents to retrieve per batch (for --full-extract)")
    parser.add_argument("--max-results", type=int,
                       help="Maximum number of results to retrieve (for --full-extract)")
    
    # Analysis options
    parser.add_argument("--analyze", action="store_true",
                       help="Perform basic analysis on the logs")
    
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

def main():
    """Main execution function."""
    args = parse_args()
    
    # Process options
    use_apache = args.apache and not args.no_apache
    use_php = args.php and not args.no_php
    
    # Build OQL query based on parameters
    oql = args.oql
    
    # Add date range to OQL if specified
    if args.from_date and args.to_date:
        date_filter = f"@timestamp:[{args.from_date}T00:00:00Z TO {args.to_date}T23:59:59Z]"
        if oql:
            oql = f"({oql}) AND {date_filter}"
        else:
            oql = date_filter
    
    # Open SSH tunnel
    print("[+] Opening SSH tunnel to secon...")
    tunnel = open_ssh_tunnel()
    time.sleep(1.5)  # Give tunnel time to initialize
    
    # Set up signal handler for graceful termination
    signal.signal(signal.SIGINT, lambda s, f: handle_sigint(s, f, tunnel))
    
    try:
        # Extract logs based on parameters
        if args.full_extract:
            print(f"[+] Extracting web logs with {'' if use_apache else 'no '}Apache and {'' if use_php else 'no '}PHP filters")
            if oql:
                print(f"[+] Additional OQL filter: {oql}")
                
            logs = get_all_logs_with_search_after(
                oql=oql,
                hours=args.hours if not (args.from_date and args.to_date) else None,
                batch_size=args.batch_size,
                index=args.index,
                apache=use_apache,
                php=use_php,
                debug=args.debug,
                dry_run=args.dry_run,
                max_results=args.max_results
            )
        else:
            print(f"[+] Extracting web logs with {'' if use_apache else 'no '}Apache and {'' if use_php else 'no '}PHP filters")
            if oql:
                print(f"[+] Additional OQL filter: {oql}")
                
            logs = get_logs(
                oql=oql,
                hours=args.hours if not (args.from_date and args.to_date) else None,
                limit=args.limit,
                index=args.index,
                apache=use_apache,
                php=use_php,
                debug=args.debug,
                dry_run=args.dry_run
            )
        
        # Process results
        if logs:
            print(f"[+] Retrieved {len(logs) if isinstance(logs, list) else 'aggregated'} logs")
            
            # Export if requested
            if args.export and not args.dry_run:
                export_logs(logs, args.export, args.format)
            
            # Display sample if not exporting
            elif not args.dry_run:
                # For large result sets, only show a sample
                if isinstance(logs, list) and len(logs) > 10:
                    print(f"[+] Showing first 10 of {len(logs)} log entries:")
                    for log in logs[:10]:
                        if args.format == "json":
                            print(json.dumps(log, indent=2))
                        else:
                            print(f"{log.get('@timestamp', 'N/A')} - {log.get('message', 'No message')[:100]}")
                    
                    if not args.export:
                        print("[!] Use --export option to save all results to a file")
                else:
                    # Display all logs for smaller result sets
                    formatted_logs = format_logs(logs, args.format)
                    for log_entry in formatted_logs[:min(len(formatted_logs), 100)]:  # Limit displayed entries
                        print(log_entry)
                    
                    if len(formatted_logs) > 100:
                        print(f"[!] Displaying only first 100 of {len(formatted_logs)} entries")
        else:
            print("[!] No web logs found matching the criteria")
        
        # Perform analysis if requested
        if args.analyze and logs and isinstance(logs, list) and not args.dry_run:
            # Simple analysis of web logs
            print("\n[+] Web Log Analysis:")
            
            # Count log types
            apache_logs = sum(1 for log in logs if "apache" in log.get("message", "").lower())
            httpd_logs = sum(1 for log in logs if "httpd" in log.get("message", "").lower())
            php_logs = sum(1 for log in logs if "php" in log.get("message", "").lower())
            
            print(f"  - Apache/HTTP logs: {apache_logs + httpd_logs}")
            print(f"  - PHP logs: {php_logs}")
            
            # Extract HTTP status codes (common format: HTTP/1.1" 200)
            status_codes = {}
            for log in logs:
                message = log.get("message", "")
                match = re.search(r'HTTP/\d\.\d"\s+(\d{3})', message)
                if match:
                    status = match.group(1)
                    if status not in status_codes:
                        status_codes[status] = 0
                    status_codes[status] += 1
            
            if status_codes:
                print("\n  HTTP Status Codes:")
                for status, count in sorted(status_codes.items()):
                    status_desc = {
                        '200': 'OK',
                        '301': 'Moved Permanently',
                        '302': 'Found',
                        '304': 'Not Modified',
                        '400': 'Bad Request',
                        '401': 'Unauthorized',
                        '403': 'Forbidden',
                        '404': 'Not Found',
                        '500': 'Internal Server Error',
                        '502': 'Bad Gateway',
                        '503': 'Service Unavailable'
                    }.get(status, 'Unknown')
                    print(f"    {status} ({status_desc}): {count}")
            
            # Extract PHP errors
            php_errors = {}
            for log in logs:
                message = log.get("message", "")
                if "php" in message.lower():
                    match = re.search(r'PHP\s+(\w+):', message)
                    if match:
                        error_type = match.group(1)
                        if error_type not in php_errors:
                            php_errors[error_type] = 0
                        php_errors[error_type] += 1
            
            if php_errors:
                print("\n  PHP Error Types:")
                for error_type, count in sorted(php_errors.items()):
                    print(f"    {error_type}: {count}")
            
            # Extract request methods (GET, POST, etc.)
            methods = {}
            for log in logs:
                message = log.get("message", "")
                match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+', message)
                if match:
                    method = match.group(1)
                    if method not in methods:
                        methods[method] = 0
                    methods[method] += 1
            
            if methods:
                print("\n  HTTP Methods:")
                for method, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
                    print(f"    {method}: {count}")
            
            # Look for potential security issues
            security_patterns = {
                'SQL Injection': [r"('|%27)(\s)?(or|OR|Or)(\s)?('|%27)", r"union\s+select", r"--\s+"],
                'XSS': [r"<script", r"javascript:", r"alert\(", r"onerror="],
                'Path Traversal': [r"\.\.\/", r"\.\.\\", r"%2e%2e%2f"],
                'Command Injection': [r";\s*\w+", r"\|\s*\w+", r"`\w+`"]
            }
            
            security_issues = {}
            for log in logs:
                message = log.get("message", "")
                for issue_type, patterns in security_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, message):
                            if issue_type not in security_issues:
                                security_issues[issue_type] = 0
                            security_issues[issue_type] += 1
                            break
                            
            if security_issues:
                print("\n  Potential Security Issues:")
                for issue_type, count in sorted(security_issues.items()):
                    print(f"    {issue_type}: {count} suspicious requests")
    
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1
    
    finally:
        # Close SSH tunnel
        print("[+] Closing SSH tunnel...")
        tunnel.terminate()
        tunnel.wait()

if __name__ == "__main__":
    sys.exit(main())
