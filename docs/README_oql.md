# Security Onion Query Language (OQL) Examples

The enhanced `get_data.py` script now supports Onion Query Language (OQL) for powerful and flexible querying of your SecurityOnion logs. 

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

## Time-Based Examples

You can combine OQL with the `--hours` parameter for time-based filtering:

```bash
# Find authentication failures in the last 24 hours
./get_data.py --oql "event.category:authentication event.outcome:failure" --hours 24

# Group by source IP for firewall blocks in the last hour
./get_data.py --oql "observer.type:firewall event.action:blocked | groupby source.ip" --hours 1
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
./get_data.py --oql "host.name:webserver1" --hours 48
```

Note: The OQL implementation in this script is a simplified version and supports basic field matching and groupby operations. It may not support all features of the full Security Onion Query Language.
