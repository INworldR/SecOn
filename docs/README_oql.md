# Security Onion Query Language (OQL) Examples

The enhanced `get_data.py` script now supports Onion Query Language (OQL) for powerful and flexible querying of your SecurityOnion logs, including pagination for retrieving large datasets.

## Basic OQL Examples

```bash
# Filter logs observer.type:firewall
./get_data.py --oql "observer.type:firewall | groupby event.action" --hours 24
./get_data.py --oql "observer.type:firewall" --hours 24

# Filter logs from hosts starting with 'ww'
./get_data.py --oql "host.name: ww*"

# Find all logs from firewalls with destination port 143 (IMAP)
./get_data.py --oql "observer.type:firewall destination.port:143"

# Look for failed login attempts
./get_data.py --oql "event.action:logon_failed"

# Filter logs by source IP and event type
./get_data.py --oql "source.ip:192.168.1.10 event.category:authentication"
```

## Date-Based Filtering

OQL now supports sophisticated date-based filtering for the `@timestamp` field:

```bash
# Get logs from a specific date (full day)
./get_data.py --oql "observer.type:firewall @timestamp:2025-03-27" --full-extract

# Get logs from a specific date range
./get_data.py --oql "observer.type:firewall @timestamp:[2025-03-25 TO 2025-03-27]" --full-extract

# Get logs after a specific date and time
./get_data.py --oql "observer.type:firewall @timestamp:>=2025-03-27T12:00:00Z" --full-extract

# Get logs before a specific date and time
./get_data.py --oql "observer.type:firewall @timestamp:<=2025-03-28T00:00:00Z" --full-extract
```

## Aggregation Examples

OQL supports aggregation operations with the `|` operator:

```bash
# Group firewall events by action
./get_data.py --oql "observer.type:firewall | groupby event.action"

# Group authentication events by source IP and outcome
./get_data.py --oql "event.category:authentication | groupby source.ip,event.outcome"

# Group web traffic by user agent
./get_data.py --oql "network.protocol:http | groupby user_agent.original"

# Find top source IPs for failed authentication
./get_data.py --oql "event.category:authentication event.outcome:failure | groupby source.ip"
```

## Large Dataset Retrieval

Using the `--full-extract` flag enables pagination to retrieve more than the default Elasticsearch limit of 10,000 documents:

```bash
# Retrieve all firewall logs from the last 24 hours
./get_data.py --oql "observer.type:firewall" --hours 24 --full-extract --export data/firewall_logs.json

# Customize batch size for performance tuning
./get_data.py --oql "observer.type:firewall" --full-extract --batch-size 2000 --export data/firewall_logs.json

# Limit the maximum number of results
./get_data.py --oql "observer.type:firewall" --full-extract --max-results 50000 --export data/firewall_logs.json

# Split data collection by date for very large datasets
./get_data.py --oql "observer.type:firewall @timestamp:2025-03-27" --full-extract --export data/firewall_logs_day1.json
./get_data.py --oql "observer.type:firewall @timestamp:2025-03-28" --full-extract --export data/firewall_logs_day2.json
```

## Logical Operators

OQL supports logical operators for complex queries:

```bash
# Find events from a specific source IP AND with a specific event action
./get_data.py --oql "source.ip:192.168.1.10 AND event.action:logon_failed"

# Find events matching either of two conditions
./get_data.py --oql "event.action:logon_failed OR event.action:authentication_failed"

# Combine multiple operators
./get_data.py --oql "(source.ip:192.168.1.10 OR source.ip:192.168.1.11) AND event.category:authentication"
```

## Output Format Examples

Control the output format with the `--format` parameter:

```bash
# Get JSON-formatted output for an OQL query
./get_data.py --oql "event.category:malware | groupby host.name" --format json

# Get YAML-formatted output for an OQL query
./get_data.py --oql "source.port:22 | groupby destination.ip" --format yaml
```

## Complex Examples

```bash
# Find web servers that have been accessed from specific network
./get_data.py --oql "service.type:web source.ip:10.0.0.* | groupby destination.ip"

# Identify mail servers with authentication failures
./get_data.py --oql "service.type:mail event.outcome:failure | groupby host.name,source.ip"

# Find all events from a specific host within a time range
./get_data.py --oql "host.name:webserver1 @timestamp:[2025-03-25 TO 2025-03-27]" --full-extract
```

## Pagination Methods

The script will automatically attempt different pagination methods when using `--full-extract`:

1. **PIT + search_after** (most efficient, but requires Elasticsearch PIT API)
2. **Plain search_after** (efficient alternative if PIT is unavailable)
3. **from/size pagination** (fallback method, limited to 10,000 documents)

Note: The OQL implementation in this script is a simplified version and supports basic field matching, date ranges, logical operators, and groupby operations. It may not support all features of the full Security Onion Query Language.
