# Analysis Scripts Guide

This guide provides comprehensive documentation for the custom Python analysis scripts developed for the SecOn project. These scripts enhance SecurityOnion's capabilities with advanced data analysis and visualization features.

## Overview

The SecOn analysis scripts extend SecurityOnion's functionality with:

- Advanced data extraction from Elasticsearch
- Sophisticated threat detection using data science techniques
- Custom visualization through JupyterLab notebooks
- APT pattern detection and sophisticated attack classification
- Integration with SecurityOnion's alerting mechanisms

## Prerequisites

Before using the analysis scripts, ensure your environment meets these requirements:

- Python 3.12 or higher
- Virtual environment (managed using conda or venv)
- Required Python packages installed (defined in `environment.yml`)
- Access to SecurityOnion's Elasticsearch instance
- JupyterLab for interactive analysis (optional)

Set up the environment:

```bash
# Clone the repository
git clone git@github.com:INworldR/SecOn.git
cd SecOn

# Set up Python environment
make setup

# Configure environment variables
cp conf/example.env conf/.env
# Edit .env file with your SecurityOnion credentials and settings
```

## Core Scripts

### Data Extraction Script: `get_data.py`

The `get_data.py` script extracts data from SecurityOnion's Elasticsearch instance with extensive filtering capabilities.

#### Basic Usage

```bash
# Extract logs from the last 24 hours
python src/get_data.py --hours 24

# Filter by program/service
python src/get_data.py --hours 24 --program sshd

# Filter by syslog priority
python src/get_data.py --hours 24 --priority 3

# Search for specific patterns
python src/get_data.py --hours 24 --pattern "Failed password"

# Use Onion Query Language (OQL) for complex queries
python src/get_data.py --oql "event.dataset:syslog AND source.ip:10.5.0.0/16"

# Select output format
python src/get_data.py --hours 24 --format json
```

#### Advanced Features

The latest version (0.3.0) includes enhanced data extraction capabilities:

```bash
# Full data extraction with pagination
python src/get_data.py --oql "event.dataset:syslog" --full-extract

# Control batch size for pagination
python src/get_data.py --oql "event.dataset:syslog" --full-extract --batch-size 1000

# Limit total number of results
python src/get_data.py --oql "event.dataset:syslog" --full-extract --max-results 50000

# Extract data for specific date range
python src/get_data.py --oql "event.dataset:syslog @timestamp:[2025-03-25 TO 2025-03-28]"

# Export results to file
python src/get_data.py --oql "event.dataset:syslog" --export data/extracted_logs.json
```

#### SSH Tunnel Configuration

Configure SSH tunnel settings in your `.env` file:

```
SO_HOST=securityonion.example.com
SO_USER=analyst
SO_SSH_KEY=/path/to/private_key
ES_HOST=localhost
ES_PORT=9200
ES_USER=elastic
ES_PASSWORD=your_password
```

### Enhanced Analysis Script: `analyse_data_enhanced.py`

The `analyse_data_enhanced.py` script performs advanced security analysis on extracted log data.

#### Basic Usage

```bash
# Analyze the most recent JSON file in data directory
python src/analysis/analyse_data_enhanced.py

# Analyze a specific file
python src/analysis/analyse_data_enhanced.py data/firewall_logs.json

# Save analysis results
python src/analysis/analyse_data_enhanced.py data/firewall_logs.json --output results/analysis_report.json

# Verbose output for debugging
python src/analysis/analyse_data_enhanced.py --verbose
```

#### JSON Error Handling

For handling JSON file issues:

```bash
# Show context around JSON parsing errors
python src/analysis/analyse_data_enhanced.py data/corrupted_logs.json --show-error-context

# Attempt to fix corrupted JSON by truncating at error point
python src/analysis/analyse_data_enhanced.py data/corrupted_logs.json --truncate-json
```

#### Analysis Features

The script provides the following analysis capabilities:

1. **Attack Pattern Detection**
   - Identifies attack patterns based on source IPs, targeted ports, and actions
   - Classifies attacks by sophistication level (LOW, MEDIUM, HIGH, APT)
   
2. **Sophistication Classification**
   - LOW: Basic scanning or opportunistic attacks
   - MEDIUM: Targeted scanning or service-specific attacks
   - HIGH: Coordinated, multi-vector or persistent attacks
   - APT: Advanced Persistent Threat indicators

3. **APT Pattern Detection**
   - Long duration, low-volume targeted attacks
   - Administrative service targeting with persistence
   - Evasion techniques

4. **Attack Grouping**
   - Groups attacks by common patterns to identify campaigns
   - Time-based grouping for related attacks
   - Target-based grouping for multi-stage attacks

### JSON Repair Utility: `fix_merged_json.py`

The `fix_merged_json.py` utility repairs incorrectly merged JSON arrays, a common issue when aggregating multiple JSON files.

#### Usage

```bash
# Fix corrupted JSON file
python src/utils/fix_merged_json.py data/corrupted.json data/fixed.json
```

### Batch Data Collection: `get_data.sh`

The `get_data.sh` script automates data collection over multiple days and hours.

#### Usage

```bash
# Collect firewall logs for date range
./get_data.sh 
```

## JupyterLab Integration

### Starting JupyterLab

Use the provided script to start JupyterLab in a managed environment:

```bash
# Start JupyterLab on default port (8898)
./start-jupyterlab.sh

# Start JupyterLab on custom port
./start-jupyterlab.sh -p 8899
```

### Example Notebooks

The project includes example notebooks for common analysis tasks:

- `notebooks/01_basic_traffic_analysis.ipynb`: Basic traffic pattern analysis
- `notebooks/02_attack_pattern_detection.ipynb`: Detecting common attack patterns
- `notebooks/03_sophisticated_attack_analysis.ipynb`: Analysis of sophisticated attacks
- `notebooks/04_visualization_examples.ipynb`: Data visualization examples
- `notebooks/05_apt_detection.ipynb`: APT pattern detection techniques

## Advanced Analysis Techniques

### Threat Intelligence Integration

Integrate threat intelligence feeds with analysis:

```python
# Example code from notebooks/threat_intelligence_integration.ipynb
from src.analysis.threat_intelligence import ThreatIntelligence

# Initialize threat intelligence module
ti = ThreatIntelligence(api_key="your_api_key")

# Check IP addresses against threat intelligence
results = ti.check_ip_reputation(ip_addresses)

# Visualize threat intelligence data
ti.visualize_threat_landscape(results)
```

### Machine Learning Models

The SecOn project includes preliminary machine learning models for anomaly detection:

```python
# Example code from notebooks/anomaly_detection.ipynb
from src.ml.anomaly_detection import IsolationForestDetector

# Initialize detector
detector = IsolationForestDetector()

# Train model on normal traffic
detector.train(normal_traffic_data)

# Detect anomalies
anomalies = detector.detect(test_data)

# Visualize anomalies
detector.plot_anomalies(test_data, anomalies)
```

### Attack Pattern Library

The `attack_patterns.py` module provides a library of common attack patterns:

```python
# Example usage in custom scripts
from src.analysis.attack_patterns import SSHBruteForcePattern, SQLInjectionPattern

# Initialize pattern detectors
ssh_detector = SSHBruteForcePattern()
sqli_detector = SQLInjectionPattern()

# Detect patterns in log data
ssh_attacks = ssh_detector.detect(log_data)
sqli_attacks = sqli_detector.detect(log_data)
```

## Automation and Integration

### Scheduled Analysis

Set up scheduled analysis tasks using cron:

```bash
# Edit crontab
crontab -e

# Add scheduled analysis (hourly)
0 * * * * cd /path/to/SecOn && python src/analysis/analyse_data_enhanced.py --output results/hourly_$(date +\%Y\%m\%d\%H).json

# Add scheduled comprehensive analysis (daily)
0 0 * * * cd /path/to/SecOn && python src/analysis/daily_comprehensive_analysis.py
```

### SecurityOnion Integration

Integrate analysis results back into SecurityOnion:

```python
# Example code from src/integration/so_integration.py
from src.integration.so_integration import SecurityOnionIntegrator

# Initialize integrator
so_integrator = SecurityOnionIntegrator(
    host="localhost",
    port=9200,
    username="elastic",
    password="your_password"
)

# Send analysis results back to SecurityOnion
so_integrator.send_analysis_results(analysis_results)
```

## Development and Extension

### Creating New Analysis Modules

To create new analysis modules:

1. Create a new Python file in the `src/analysis` directory
2. Define a class that inherits from the base `Analyzer` class
3. Implement required methods for data processing and analysis
4. Register the analyzer in the analyzer registry

Example:

```python
# src/analysis/custom_analyzer.py
from src.analysis.base import Analyzer, register_analyzer

@register_analyzer("custom")
class CustomAnalyzer(Analyzer):
    """Custom analyzer for specific use case."""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.name = "Custom Analyzer"
        
    def analyze(self, data):
        """Perform analysis on the provided data."""
        results = self._process_data(data)
        return results
        
    def _process_data(self, data):
        # Custom processing logic
        return processed_data
```

### Implementing Custom Visualizations

For custom visualizations:

1. Create a new Python file in `src/visualization`
2. Define visualization functions using matplotlib, seaborn, or other libraries
3. Ensure compatibility with JupyterLab

Example:

```python
# src/visualization/custom_plots.py
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

def plot_attack_timeline(data, title="Attack Timeline"):
    """Plot timeline of attacks with sophistication levels."""
    df = pd.DataFrame(data)
    
    plt.figure(figsize=(12, 6))
    sns.scatterplot(
        x="timestamp", 
        y="target",
        hue="sophistication",
        size="count",
        data=df
    )
    
    plt.title(title)
    plt.xlabel("Time")
    plt.ylabel("Target System")
    plt.tight_layout()
    
    return plt.gcf()
```

### Extending Data Collection

To add support for new data sources:

1. Modify `get_data.py` to support the new source
2. Create appropriate parsers in `src/parsers`
3. Update documentation for the new data source

Example for a custom API source:

```python
# src/parsers/custom_api_parser.py
import requests
import json

def fetch_from_api(api_url, api_key, params=None):
    """Fetch data from custom API."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(api_url, headers=headers, params=params)
    response.raise_for_status()
    
    return response.json()

def parse_api_data(data):
    """Parse data from custom API into standard format."""
    parsed_data = []
    
    for item in data.get("items", []):
        parsed_item = {
            "timestamp": item.get("event_time"),
            "source_ip": item.get("source", {}).get("ip"),
            "destination_ip": item.get("destination", {}).get("ip"),
            "event_type": item.get("type"),
            "severity": item.get("severity"),
            # Add more fields as needed
        }
        parsed_data.append(parsed_item)
    
    return parsed_data
```

## Performance Considerations

### Handling Large Datasets

When working with large datasets:

```python
# Example of chunked processing for large datasets
def process_large_dataset(file_path, chunk_size=10000):
    """Process large JSON dataset in chunks."""
    results = []
    
    # Process in chunks using pandas
    for chunk in pd.read_json(file_path, lines=True, chunksize=chunk_size):
        # Process chunk
        chunk_results = analyze_chunk(chunk)
        results.extend(chunk_results)
    
    return results

def analyze_chunk(chunk):
    """Analyze a single chunk of data."""
    # Implement analysis logic
    return chunk_results
```

### Optimizing Analysis Scripts

Tips for optimizing analysis performance:

1. Use vectorized operations with NumPy and Pandas instead of loops
2. Implement multiprocessing for CPU-intensive tasks
3. Use efficient data structures (e.g., sets for membership tests)
4. Cache intermediate results for repeated analyses

Example of multiprocessing implementation:

```python
# Example of multiprocessing for parallel analysis
import multiprocessing as mp
from functools import partial

def analyze_parallel(data, analyzer_func, n_processes=None):
    """Run analysis in parallel."""
    if n_processes is None:
        n_processes = mp.cpu_count() - 1
    
    # Split data into chunks
    chunk_size = len(data) // n_processes
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    # Process in parallel
    with mp.Pool(n_processes) as pool:
        results = pool.map(analyzer_func, chunks)
    
    # Combine results
    combined_results = []
    for chunk_result in results:
        combined_results.extend(chunk_result)
    
    return combined_results
```

## Troubleshooting

### Common Issues

#### JSON Parsing Errors

```bash
# Fix JSON parsing errors
python src/utils/fix_merged_json.py data/corrupted.json data/fixed.json
```

#### Elasticsearch Connection Issues

```bash
# Test Elasticsearch connection
python -c "from src.utils.es_utils import test_connection; test_connection()"

# Debug Elasticsearch queries
python src/get_data.py --debug --hours 1
```

#### Memory Errors with Large Datasets

```bash
# Process data in chunks
python src/analysis/analyse_data_enhanced.py --chunk-size 10000

# Use memory-efficient options
python src/analysis/analyse_data_enhanced.py --memory-efficient
```

### Logging and Debugging

Enable detailed logging for troubleshooting:

```bash
# Set environment variable for debug logging
export SECON_LOG_LEVEL=DEBUG

# Run with debug logging
python src/analysis/analyse_data_enhanced.py --verbose
```

## Examples and Use Cases

### Use Case: Detecting SSH Brute Force Attacks

```bash
# Extract SSH-related logs
python src/get_data.py --oql "event.dataset:syslog AND message:*sshd*" --export data/ssh_logs.json

# Analyze for brute force patterns
python src/analysis/analyse_data_enhanced.py data/ssh_logs.json --output results/ssh_analysis.json

# Review in JupyterLab
jupyter lab notebooks/ssh_brute_force_analysis.ipynb
```

### Use Case: Analyzing Web Server Attacks

```bash
# Extract web server logs
python src/get_data.py --oql "source.application:*httpd* OR source.application:*nginx*" --export data/web_logs.json

# Analyze for web attack patterns
python src/analysis/web_attack_analyzer.py data/web_logs.json --output results/web_analysis.json
```

### Use Case: Identifying Advanced Persistent Threats

```bash
# Extract logs for the last 30 days
python src/get_data.py --days 30 --export data/month_logs.json

# Run APT detection analysis
python src/analysis/apt_detector.py data/month_logs.json --output results/apt_analysis.json

# Generate comprehensive report
python src/reporting/generate_report.py results/apt_analysis.json --template apt_report --output reports/monthly_apt_report.pdf
```

## Next Steps

After setting up the analysis scripts, proceed to:

1. [Alerts Configuration](alerts.md) - Configuring alerts based on analysis results
2. [Development Guidelines](development.md) - Guidelines for contributing to the project

---

This analysis scripts guide is part of the SecOn project documentation. For any questions or issues specific to the project implementation, contact the project lead.
