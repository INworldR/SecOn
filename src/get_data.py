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

class ElasticsearchHelper:
    """Helper class for Elasticsearch operations."""
    
    def __init__(self, base_url, username, password, debug=False):
        """Initialize with Elasticsearch connection details."""
        self.base_url = base_url
        self.username = username
        self.password = password
        self.debug = debug
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {"Content-Type": "application/json"}
        
    def open_pit(self, index="logs-*", keep_alive="5m"):
        """Open a Point in Time (PIT) for consistent search results.
        
        Args:
            index (str): The index or index pattern to create a PIT for
            keep_alive (str): How long to keep the PIT alive (e.g. "5m" for 5 minutes)
            
        Returns:
            str: The PIT ID if successful, None otherwise
        """
        url = f"{self.base_url.split('/_search')[0]}/_pit"
        
        try:
            response = requests.post(
                url,
                auth=self.auth,
                headers=self.headers,
                json={"index": index, "keep_alive": keep_alive},
                verify=False
            )
            response.raise_for_status()
            result = response.json()
            if self.debug:
                print(f"[+] PIT opened: {result.get('id', 'No ID returned')[:20]}...")
            return result.get("id")
        except requests.exceptions.RequestException as e:
            print(f"[!] Failed to open PIT: {e}")
            return None
            
    def close_pit(self, pit_id):
        """Close a Point in Time to free up resources.
        
        Args:
            pit_id (str): The PIT ID to close
            
        Returns:
            bool: True if successful, False otherwise
        """
        url = f"{self.base_url.split('/_search')[0]}/_pit"
        
        try:
            response = requests.delete(
                url,
                auth=self.auth,
                headers=self.headers,
                json={"id": pit_id},
                verify=False
            )
            response.raise_for_status()
            if self.debug:
                print(f"[+] PIT closed: {pit_id[:20]}...")
            return True
        except requests.exceptions.RequestException as e:
            print(f"[!] Failed to close PIT: {e}")
            return False
            
    def search_with_pit(self, pit_id, query, search_after=None, size=1000, keep_alive="5m"):
        """Perform a search using a Point in Time ID.
        
        Args:
            pit_id (str): The PIT ID to use
            query (dict): The Elasticsearch query
            search_after (list): Optional list of sort values for pagination
            size (int): Number of documents to retrieve per batch
            keep_alive (str): How long to extend the PIT lifespan
            
        Returns:
            dict: The search results
        """
        url = f"{self.base_url.split('/_search')[0]}/_search"
        
        body = {
            "size": size,
            "query": query,
            "pit": {
                "id": pit_id,
                "keep_alive": keep_alive
            },
            "sort": [
                {"@timestamp": "desc"},
                {"_id": "asc"}  # Secondary sort for stability
            ]
        }
        
        if search_after:
            body["search_after"] = search_after
            
        try:
            response = requests.post(
                url,
                auth=self.auth,
                headers=self.headers,
                json=body,
                verify=False
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[!] Search request failed: {e}")
            return {}

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

def parse_term(term, debug=False):
    """Helper function to parse a single OQL term into an Elasticsearch query clause.
    
    Args:
        term (str): The OQL term to parse
        debug (bool): Enable verbose debug output
        
    Returns:
        dict: Elasticsearch query clause
    """
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
    
    # Check if this is an aggregation query
    parts = oql.split('|', 1)
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
        return [hit["_source"] for hit in hits]

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return []

def get_all_logs_with_search_after(oql, hours=None, batch_size=1000, index="logs-*", debug=False, dry_run=False, 
                   progress_interval=5, max_results=None):
    """
    Fetch all logs from Elasticsearch using plain search_after pagination without PIT.
    
    Args:
        oql (str): Onion Query Language query string.
        hours (int): Optional time filter (hours back).
        batch_size (int): Number of documents to retrieve per batch.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don't send request.
        progress_interval (int): Seconds between progress updates.
        max_results (int): Maximum number of results to return (None for all).
        
    Returns:
        list[dict]: A list of log entries.
    """
    # Convert OQL to Elasticsearch query
    query = oql_to_elasticsearch(oql, hours, debug)
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
        
        print(f"[+] Starting extraction with batch size {batch_size} using search_after pagination...")
        
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
                
            # Extract documents
            batch_docs = [hit["_source"] for hit in hits]
            all_results.extend(batch_docs)
            total_retrieved += len(batch_docs)
            
            # Update progress periodically
            current_time = time.time()
            if current_time - last_progress_time >= progress_interval:
                print(f"[+] Retrieved {total_retrieved} documents so far (batch {batch_num})...")
                last_progress_time = current_time
                
            # Prepare for next iteration
            last_hit = hits[-1]
            search_after = last_hit["sort"]
            batch_num += 1
            
            # Check if we've reached the maximum requested number of results
            if max_results and total_retrieved >= max_results:
                print(f"[+] Reached maximum requested results: {max_results}")
                break
        
        print(f"[+] Extraction complete. Retrieved {total_retrieved} documents in {batch_num-1} batches.")
        return all_results
        
    except Exception as e:
        print(f"[!] Error during extraction: {e}")
        return []

def get_all_logs_with_from_size(oql, hours=None, batch_size=1000, index="logs-*", debug=False, dry_run=False, 
                    progress_interval=5, max_results=None):
    """
    Fetch logs from Elasticsearch using from/size pagination (limited to 10,000 results).
    
    Args:
        oql (str): Onion Query Language query string.
        hours (int): Optional time filter (hours back).
        batch_size (int): Number of documents to retrieve per batch.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don't send request.
        progress_interval (int): Seconds between progress updates.
        max_results (int): Maximum number of results to return (None for all).
        
    Returns:
        list[dict]: A list of log entries.
    """
    # Convert OQL to Elasticsearch query
    query = oql_to_elasticsearch(oql, hours, debug)
    url = ELASTIC_URL.replace("logs-*", index)
    
    if dry_run:
        print(f"Query URL: {url}")
        print(f"Query (from/size pagination will be used):\n{json.dumps(query, indent=2)}")
        return []
    
    try:
        all_results = []
        from_position = 0
        last_progress_time = time.time()
        total_retrieved = 0
        batch_num = 1
        
        print(f"[+] Starting extraction with batch size {batch_size} using from/size pagination...")
        print("[!] Note: This method is limited to retrieving a maximum of 10,000 results.")
        
        while True:
            # Prepare the request body
            request_body = {
                "query": query,
                "from": from_position,
                "size": batch_size,
                "sort": [{"@timestamp": "desc"}]
            }
            
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
                
            # Extract documents
            batch_docs = [hit["_source"] for hit in hits]
            all_results.extend(batch_docs)
            total_retrieved += len(batch_docs)
            
            # Update progress periodically
            current_time = time.time()
            if current_time - last_progress_time >= progress_interval:
                print(f"[+] Retrieved {total_retrieved} documents so far (batch {batch_num})...")
                last_progress_time = current_time
                
            # Prepare for next iteration
            from_position += batch_size
            batch_num += 1
            
            # Check if we've reached the maximum requested number of results
            if max_results and total_retrieved >= max_results:
                print(f"[+] Reached maximum requested results: {max_results}")
                break
                
            # Check if we're approaching the 10,000 limit
            if from_position + batch_size > 10000:
                remaining = max(0, 10000 - from_position)
                if remaining == 0:
                    print("[!] Reached Elasticsearch's 10,000 document limit for from/size pagination.")
                    break
                
                # Adjust the batch size for the final request to not exceed 10,000
                if debug:
                    print(f"[*] Adjusting final batch size to {remaining}")
        
        print(f"[+] Extraction complete. Retrieved {total_retrieved} documents in {batch_num-1} batches.")
        return all_results
        
    except Exception as e:
        print(f"[!] Error during extraction: {e}")
        return []

def get_all_logs_with_pit(oql, hours=None, batch_size=1000, index="logs-*", debug=False, dry_run=False, 
                 progress_interval=5, max_results=None):
    """
    Fetch all logs from Elasticsearch using OQL with search_after pagination and PIT.
    
    Args:
        oql (str): Onion Query Language query string.
        hours (int): Optional time filter (hours back).
        batch_size (int): Number of documents to retrieve per batch.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don't send request.
        progress_interval (int): Seconds between progress updates.
        max_results (int): Maximum number of results to return (None for all).
        
    Returns:
        list[dict]: A list of log entries.
    """
    # Convert OQL to Elasticsearch query
    query = oql_to_elasticsearch(oql, hours, debug)
    
    if dry_run:
        print(f"Query URL: {ELASTIC_URL}")
        print(f"Query (search_after with PIT will be used):\n{json.dumps(query, indent=2)}")
        return []
    
    # Initialize Elasticsearch helper
    es_helper = ElasticsearchHelper(ELASTIC_URL, USERNAME, PASSWORD, debug)
    
    # Open a Point in Time
    pit_id = es_helper.open_pit(index)
    if not pit_id:
        print("[!] Failed to create Point in Time.")
        return None  # Return None to indicate PIT failure
    
    try:
        all_results = []
        search_after = None
        last_progress_time = time.time()
        total_retrieved = 0
        batch_num = 1
        
        print(f"[+] Starting extraction with batch size {batch_size} using PIT...")
        
        while True:
            # Perform search
            result = es_helper.search_with_pit(pit_id, query, search_after, batch_size)
            
            # Extract hits
            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break  # No more results
                
            # Extract documents
            batch_docs = [hit["_source"] for hit in hits]
            all_results.extend(batch_docs)
            total_retrieved += len(batch_docs)
            
            # Update progress periodically
            current_time = time.time()
            if current_time - last_progress_time >= progress_interval:
                print(f"[+] Retrieved {total_retrieved} documents so far (batch {batch_num})...")
                last_progress_time = current_time
                
            # Prepare for next iteration
            last_hit = hits[-1]
            search_after = last_hit["sort"]
            batch_num += 1
            
            # Check if we've reached the maximum requested number of results
            if max_results and total_retrieved >= max_results:
                print(f"[+] Reached maximum requested results: {max_results}")
                break
        
        print(f"[+] Extraction complete. Retrieved {total_retrieved} documents in {batch_num-1} batches.")
        return all_results
        
    except Exception as e:
        print(f"[!] Error during extraction: {e}")
        return []
    finally:
        # Always close the PIT when done
        if pit_id:
            es_helper.close_pit(pit_id)

def get_all_logs(oql, hours=None, batch_size=1000, index="logs-*", debug=False, dry_run=False, 
                 progress_interval=5, max_results=None):
    """
    Fetch all logs from Elasticsearch using the best available pagination method.
    
    Args:
        oql (str): Onion Query Language query string.
        hours (int): Optional time filter (hours back).
        batch_size (int): Number of documents to retrieve per batch.
        index (str): Index pattern to search within.
        debug (bool): Enable verbose debug output.
        dry_run (bool): If True, show query but don't send request.
        progress_interval (int): Seconds between progress updates.
        max_results (int): Maximum number of results to return (None for all).
        
    Returns:
        list[dict]: A list of log entries.
    """
    # Check if this is an aggregation query
    parts = oql.split('|', 1)
    pipeline_part = parts[1].strip() if len(parts) > 1 else None
    
    if pipeline_part and pipeline_part.startswith('groupby'):
        print("[!] Full extraction with pagination is not supported for aggregation queries.")
        print("[!] Falling back to standard method.")
        return get_logs(oql, hours, None, index, debug, dry_run)
    
    # Try PIT + search_after first (most efficient)
    print("[+] Attempting extraction using Point in Time (PIT) + search_after...")
    results = get_all_logs_with_pit(oql, hours, batch_size, index, debug, dry_run, progress_interval, max_results)
    
    if results is None:  # PIT creation failed
        # Try plain search_after (second best)
        print("[+] Falling back to plain search_after pagination...")
        results = get_all_logs_with_search_after(oql, hours, batch_size, index, debug, dry_run, progress_interval, max_results)
        
        if not results and not dry_run:
            # As a last resort, try from/size (limited to 10,000)
            print("[+] Trying from/size pagination as a last resort...")
            results = get_all_logs_with_from_size(oql, hours, batch_size, index, debug, dry_run, progress_interval, max_results)
    
    return results

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
    
    # Full extraction parameters
    parser.add_argument("--full-extract", action="store_true",
                       help="Extract all matching documents using search_after pagination")
    parser.add_argument("--batch-size", type=int, default=1000,
                       help="Number of documents to retrieve per batch (for --full-extract)")
    parser.add_argument("--max-results", type=int,
                       help="Maximum number of results to retrieve (for --full-extract)")
    
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
    
    # Set up signal handler for graceful termination
    signal.signal(signal.SIGINT, lambda s, f: handle_sigint(s, f, tunnel))

    try:
        if args.full_extract:
            start_time = time.time()
            logs = get_all_logs(
                oql=args.oql,
                hours=args.hours,
                batch_size=args.batch_size,
                index=args.index,
                debug=args.debug,
                dry_run=args.dry_run,
                max_results=args.max_results
            )
            end_time = time.time()
            if logs and not args.dry_run:
                print(f"[+] Retrieved {len(logs)} documents in {end_time - start_time:.2f} seconds")
        else:
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
                    # For large result sets, only show summary and first few entries
                    if args.full_extract and len(logs) > 10:
                        print(f"[+] Retrieved {len(logs)} documents. Showing first 10:")
                        formatted_logs = format_logs(logs[:10], args.format)
                        for log_entry in formatted_logs:
                            print(log_entry)
                        print(f"[+] ... and {len(logs) - 10} more. Use --export to save all results.")
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
