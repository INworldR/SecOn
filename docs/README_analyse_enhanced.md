# 📊 Enhanced Log Analysis for SecurityOnion

## Overview

`analyse_data_enhanced.py` is an advanced analysis script designed to process SecurityOnion log data with a focus on threat detection and analysis. It extracts meaningful patterns from firewall logs to identify attack patterns, classify threats by sophistication level, and detect potential Advanced Persistent Threats (APTs).

This script is part of the SecOn security monitoring toolkit, designed to complement SecurityOnion's built-in capabilities with specialized Python-based analysis.

## Features

- **Attack Pattern Detection**: Identifies common attack patterns and classifies them based on behavior
- **Sophistication Classification**: Classifies attackers into four levels (LOW, MEDIUM, HIGH, APT)
- **APT Detection**: Applies specialized heuristics to identify potential Advanced Persistent Threat activity
- **Attack Grouping**: Groups related attacks to identify campaigns based on timing, targets, and methods
- **Comprehensive Reporting**: Generates detailed reports in both human-readable and JSON formats

## Installation

The script is designed to work within the SecOn environment. Make sure you have the required dependencies installed:

```bash
# With the environment activated
pip install pandas numpy
```

## Usage

### Basic Usage

```bash
./analyse_data_enhanced.py [input_file.json] [--output results.json] [--verbose]
```

### Arguments

- `input_file.json` (optional): Path to JSON log file exported from SecurityOnion. If not specified, uses the newest JSON file in the `../data` directory.
- `--output results.json`: Save analysis results to specified JSON file
- `--verbose`: Enable verbose output for debugging

### Examples

Analyze a specific log file:
```bash
./analyse_data_enhanced.py example.json
```

Analyze the newest log file in ../data:
```bash
./analyse_data_enhanced.py
```

Save analysis results to a file:
```bash
./analyse_data_enhanced.py example.json --output analysis_results.json
```

## Understanding the Output

### Console Output

The script prints a summary of findings to the console, including:

- Overall statistics (number of logs, unique sources/destinations)
- Breakdown of attacks by sophistication level
- Most targeted ports and services
- Potential APT candidates with evidence
- Top attackers by attempt count

### Sophistication Levels

Attacks are classified into four sophistication levels:

1. **LOW**: Basic scans or opportunistic attacks
   - Single-target, short-duration events
   - Common port scans

2. **MEDIUM**: Targeted scans or specific service attacks
   - Multiple ports or targets
   - Longer duration
   - Targeting of specific services

3. **HIGH**: Coordinated, multi-vector or persistent attacks
   - Large number of attempts
   - Long duration targeting sensitive services
   - Sophisticated patterns

4. **APT**: Advanced Persistent Threat indicators
   - Long duration with careful, low-volume activity
   - Targeting of administrative interfaces
   - Evidence of evasion techniques

### APT Detection

The APT detection logic looks for:
- Long-duration, low-volume attacks (attempting to stay below detection thresholds)
- Targeting of sensitive administrative services
- Strategic targeting of database services
- Other suspicious patterns indicative of advanced threat actors

### JSON Output

The JSON output contains detailed information including:

- Summary statistics
- Attack groupings (by sophistication, service, time)
- Detailed breakdown of sophistication levels with examples
- APT candidates with supporting evidence
- Top attackers with metrics

## Integration with Other Tools

The JSON output is designed to be compatible with other analysis tools and can be used for:

- Integration with SIEM systems
- Creating custom visualizations
- Building threat intelligence databases
- Automating response workflows

## Troubleshooting

- **Missing Data Fields**: If the script reports missing fields, check that your export contains the required fields (source IP, destination IP, timestamps, etc.)
- **Memory Issues**: For very large log files, consider filtering the data before analysis
- **JSON Serialization Errors**: If you encounter errors when saving JSON, please report them (recent fixes have addressed known issues)

## Contributing

Contributions are welcome! Please follow the project's coding standards (PEP 8) and add appropriate tests for new features.
