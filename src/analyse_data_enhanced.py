#!/usr/bin/env python
"""
Enhanced analysis module for SecurityOnion log data with focus on attack pattern detection.

This script analyzes JSON data exported from SecurityOnion using the get_data.py script.
It identifies patterns in firewall logs to classify attacks by sophistication level and
detect potential APT (Advanced Persistent Threat) patterns.

Usage:
    python analyse_data_enhanced.py <input_file.json> [--output <output_file>] [--verbose]
"""

import os
import sys
import json
import argparse
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import ipaddress
import re
from typing import Dict, List, Any, Tuple, Set, Optional


class SecurityLogAnalyzer:
    """Class for analyzing SecurityOnion log data with focus on threat intelligence."""
    
    # Classification of attack sophistication levels
    SOPHISTICATION_LEVELS = {
        'LOW': 'Basic scan or opportunistic attack',
        'MEDIUM': 'Targeted scan or specific service attack',
        'HIGH': 'Coordinated, multi-vector or persistent attack',
        'APT': 'Advanced Persistent Threat indicators'
    }
    
    # Common ports and their services (for pattern detection)
    COMMON_PORTS = {
        21: 'FTP', 
        22: 'SSH', 
        23: 'Telnet', 
        25: 'SMTP', 
        53: 'DNS',
        80: 'HTTP', 
        443: 'HTTPS', 
        445: 'SMB', 
        1433: 'MSSQL', 
        3306: 'MySQL',
        3389: 'RDP', 
        5432: 'PostgreSQL', 
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT'
    }
    
    # Ports that might indicate more sophisticated attacks when targeted
    SENSITIVE_PORTS = {
        22: 'SSH',
        3389: 'RDP',
        5900: 'VNC',
        5901: 'VNC',
        5902: 'VNC',
        5903: 'VNC',
        3306: 'MySQL',
        1433: 'MSSQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        9200: 'Elasticsearch',
        9300: 'Elasticsearch',
        8080: 'HTTP-ALT'
    }
    
    def __init__(self, verbose=False):
        """Initialize the analyzer with configuration options."""
        self.verbose = verbose
        self.df = None
        self.attack_groups = {}
        self.ip_classification = {}
        self.summary = {}
        
    def load_data(self, file_path: str) -> bool:
        """
        Load SecurityOnion log data from JSON file.
        
        Args:
            file_path: Path to JSON log file
            
        Returns:
            bool: True if loading was successful, False otherwise
        """
        try:
            # Check file extension
            if file_path.endswith('.json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            else:
                print(f"Error: Unsupported file format. Expected .json file, got: {file_path}")
                return False
                
            if self.verbose:
                print(f"Loading {len(logs)} log entries from {file_path}")
                
            # Convert to DataFrame for easier analysis
            self.df = pd.json_normalize(logs)
            
            # Basic validation of expected fields
            required_fields = ['@timestamp', 'source.ip', 'destination.ip', 'event.action']
            missing_fields = [field for field in required_fields if not any(col.startswith(field.split('.')[0]) for col in self.df.columns)]
            
            if missing_fields:
                print(f"Warning: Missing expected fields in log data: {missing_fields}")
            
            # Add analysis timestamp
            self.analysis_time = datetime.now()
            return True
            
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def preprocess_data(self) -> None:
        """
        Preprocess log data for analysis.
        - Extract relevant fields
        - Normalize timestamps
        - Filter out noise
        """
        if self.df is None or self.df.empty:
            print("No data to preprocess")
            return
            
        # Clean up and normalize field names where needed
        if 'source.ip' not in self.df.columns and 'source' in self.df.columns:
            try:
                self.df['source.ip'] = self.df['source'].apply(
                    lambda x: x.get('ip', None) if isinstance(x, dict) else None
                )
            except:
                pass
            
        if 'destination.ip' not in self.df.columns and 'destination' in self.df.columns:
            try:
                self.df['destination.ip'] = self.df['destination'].apply(
                    lambda x: x.get('ip', None) if isinstance(x, dict) else None
                )
            except:
                pass
        
        # Extract source and destination ports
        if 'source.port' not in self.df.columns and 'source' in self.df.columns:
            try:
                self.df['source.port'] = self.df['source'].apply(
                    lambda x: int(x.get('port', 0)) if isinstance(x, dict) and x.get('port') else 0
                )
            except:
                pass
                
        if 'destination.port' not in self.df.columns and 'destination' in self.df.columns:
            try:
                self.df['destination.port'] = self.df['destination'].apply(
                    lambda x: int(x.get('port', 0)) if isinstance(x, dict) and x.get('port') else 0
                )
            except:
                pass
                
        # Extract protocol if available
        if 'network.transport' not in self.df.columns and 'network' in self.df.columns:
            try:
                self.df['network.transport'] = self.df['network'].apply(
                    lambda x: x.get('transport', None) if isinstance(x, dict) else None
                )
            except:
                pass
                
        # Convert timestamp to datetime if it's a string
        if '@timestamp' in self.df.columns and self.df['@timestamp'].dtype == 'object':
            self.df['@timestamp'] = pd.to_datetime(self.df['@timestamp'])
            
        # Extract action from event
        if 'event.action' not in self.df.columns and 'event' in self.df.columns:
            try:
                self.df['event.action'] = self.df['event'].apply(
                    lambda x: x.get('action', None) if isinstance(x, dict) else None
                )
            except:
                pass
                
        # For PfSense logs, extract specific details
        if 'pfsense' in self.df.columns:
            try:
                # Extract TCP flags if available
                self.df['tcp.flags'] = self.df['pfsense'].apply(
                    lambda x: x.get('tcp', {}).get('flags', None) if isinstance(x, dict) else None
                )
            except:
                pass
        
        # Calculate time interval for analyses
        if '@timestamp' in self.df.columns:
            self.start_time = self.df['@timestamp'].min()
            self.end_time = self.df['@timestamp'].max()
            self.time_span = self.end_time - self.start_time
            
            if self.verbose:
                print(f"Data spans from {self.start_time} to {self.end_time} ({self.time_span})")
    
    def analyze_attack_patterns(self) -> None:
        """
        Analyze logs to identify attack patterns and classify threats.
        """
        if self.df is None or self.df.empty:
            print("No data to analyze")
            return
            
        # Group by source IP to identify attackers
        source_grouped = self.df.groupby('source.ip')
        
        # Dictionary to store attacker profiles
        attackers = {}
        
        for source_ip, group in source_grouped:
            # Skip if not a valid IP
            if not source_ip or pd.isna(source_ip):
                continue
                
            # Create attacker profile
            profile = {
                'ip': source_ip,
                'count': len(group),
                'first_seen': group['@timestamp'].min(),
                'last_seen': group['@timestamp'].max(),
                'duration': (group['@timestamp'].max() - group['@timestamp'].min()).total_seconds(),
                'target_count': group['destination.ip'].nunique(),
                'targets': group['destination.ip'].unique().tolist(),
                'ports_targeted': []
            }
            
            # Extract targeted ports
            if 'destination.port' in group.columns:
                ports = group['destination.port'].value_counts().to_dict()
                profile['ports_targeted'] = [(port, count) for port, count in ports.items()]
                profile['unique_ports'] = len(ports)
                
                # Check for sensitive ports
                profile['sensitive_ports'] = [
                    port for port in ports.keys() 
                    if port in self.SENSITIVE_PORTS
                ]
            
            # Analyze actions
            if 'event.action' in group.columns:
                profile['actions'] = group['event.action'].value_counts().to_dict()
                
            # Detect sophistication level
            profile['sophistication_level'] = self._determine_sophistication(profile)
            
            # Store the profile
            attackers[source_ip] = profile
        
        # Store results
        self.attackers = attackers
        
        # Create attack groups based on common patterns
        self._identify_attack_groups()
        
        # Generate overall summary
        self._generate_summary()
        
    def _determine_sophistication(self, profile: Dict) -> str:
        """
        Determine the sophistication level of an attack based on patterns.
        
        Args:
            profile: Dictionary containing attacker profile
            
        Returns:
            str: Sophistication level (LOW, MEDIUM, HIGH, APT)
        """
        # Default to LOW
        level = 'LOW'
        reasons = []
        
        # Check duration - persistent attacks may indicate higher sophistication
        if profile['duration'] > 3600:  # More than an hour
            level = 'MEDIUM'
            reasons.append(f"Attack duration: {profile['duration']/3600:.1f} hours")
        
        # Check number of targets - more targets may indicate scanning or wide attack
        if profile['target_count'] > 10:
            if level == 'LOW':
                level = 'MEDIUM'
            reasons.append(f"Multiple targets: {profile['target_count']} unique IPs")
            
        # Check for sensitive ports - targeting admin interfaces indicates sophistication
        if hasattr(profile, 'sensitive_ports') and profile['sensitive_ports']:
            level = max(level, 'MEDIUM')
            targeted_services = [f"{port} ({self.SENSITIVE_PORTS.get(port, 'Unknown')})" 
                               for port in profile['sensitive_ports']]
            reasons.append(f"Sensitive ports targeted: {', '.join(targeted_services)}")
            
        # Check for port diversity - more ports may indicate targeted attacks or scanning
        if hasattr(profile, 'unique_ports') and profile['unique_ports'] > 5:
            level = max(level, 'MEDIUM')
            reasons.append(f"Port diversity: {profile['unique_ports']} unique ports")
            
        # High number of attempts might indicate brute force or persistence
        if profile['count'] > 100:
            level = max(level, 'MEDIUM')
            if profile['count'] > 1000:
                level = 'HIGH'
            reasons.append(f"High attempt count: {profile['count']} attempts")
            
        # Check for advanced patterns indicating APT
        # 1. Long duration with low-volume, targeted attacks
        if profile['duration'] > 86400 and profile['count'] < 50 and profile['target_count'] < 3:  # > 1 day
            level = 'APT'
            reasons.append("Long duration, low volume, targeted attack pattern")
            
        # 2. Admin services targeted with persistence
        if (hasattr(profile, 'sensitive_ports') and profile['sensitive_ports'] and
            profile['duration'] > 7200):  # > 2 hours
            level = max(level, 'HIGH')
            reasons.append("Persistent targeting of administrative services")
        
        # Store reasons for classification
        profile['classification_reasons'] = reasons
        
        return level
        
    def _identify_attack_groups(self) -> None:
        """Group attacks based on similar patterns to identify campaigns."""
        if not hasattr(self, 'attackers'):
            return
            
        # Group by sophistication level
        sophistication_groups = defaultdict(list)
        for ip, profile in self.attackers.items():
            sophistication_groups[profile['sophistication_level']].append(ip)
            
        # Group by targeted services
        service_groups = defaultdict(list)
        for ip, profile in self.attackers.items():
            if hasattr(profile, 'ports_targeted') and profile['ports_targeted']:
                # Get top 3 most targeted ports
                top_ports = sorted(profile['ports_targeted'], key=lambda x: x[1], reverse=True)[:3]
                port_key = '-'.join([str(port) for port, _ in top_ports])
                service_groups[port_key].append(ip)
                
        # Group by time proximity - attacks happening within 10 minutes
        time_groups = defaultdict(list)
        sorted_attackers = sorted(
            self.attackers.items(), 
            key=lambda x: x[1]['first_seen']
        )
        
        current_group = 1
        current_time = None
        for ip, profile in sorted_attackers:
            if current_time is None:
                current_time = profile['first_seen']
                time_groups[f"timegroup_{current_group}"].append(ip)
            elif (profile['first_seen'] - current_time).total_seconds() < 600:  # 10 minutes
                time_groups[f"timegroup_{current_group}"].append(ip)
            else:
                current_group += 1
                current_time = profile['first_seen']
                time_groups[f"timegroup_{current_group}"].append(ip)
                
        # Store the groups
        self.attack_groups = {
            'by_sophistication': sophistication_groups,
            'by_service': service_groups,
            'by_time': time_groups
        }
        
    def _generate_summary(self) -> None:
        """Generate an overall summary of the analysis results."""
        if not hasattr(self, 'attackers') or not self.attackers:
            return
            
        # Count attacks by sophistication level
        sophistication_counts = Counter()
        for ip, profile in self.attackers.items():
            sophistication_counts[profile['sophistication_level']] += 1
            
        # Find most targeted ports
        all_port_targets = []
        for ip, profile in self.attackers.items():
            if hasattr(profile, 'ports_targeted') and profile['ports_targeted']:
                all_port_targets.extend([port for port, _ in profile['ports_targeted']])
        most_targeted_ports = Counter(all_port_targets).most_common(10)
        
        # Find most targeted destinations
        all_destinations = []
        for ip, profile in self.attackers.items():
            if hasattr(profile, 'targets') and profile['targets']:
                all_destinations.extend(profile['targets'])
        most_targeted_destinations = Counter(all_destinations).most_common(10)
        
        # Create summary
        self.summary = {
            'total_logs': len(self.df),
            'unique_sources': len(self.attackers),
            'unique_destinations': len(set(all_destinations)),
            'time_span': self.time_span,
            'sophistication_counts': sophistication_counts,
            'most_targeted_ports': most_targeted_ports,
            'most_targeted_destinations': most_targeted_destinations,
            'analysis_time': self.analysis_time
        }
        
    def identify_apt_patterns(self) -> List[Dict]:
        """
        Identify potential APT (Advanced Persistent Threat) patterns in the data.
        
        Returns:
            List of dictionaries with APT candidates and evidence
        """
        if not hasattr(self, 'attackers') or not self.attackers:
            return []
            
        apt_candidates = []
        
        # Look for patterns indicating APT activity
        for ip, profile in self.attackers.items():
            # Skip if already classified as APT
            if profile['sophistication_level'] == 'APT':
                apt_candidates.append({
                    'source_ip': ip,
                    'evidence': profile['classification_reasons'],
                    'first_seen': profile['first_seen'],
                    'last_seen': profile['last_seen'],
                    'duration': profile['duration'],
                    'confidence': 'High'
                })
                continue
                
            # Check for additional APT patterns not caught in initial classification
            evidence = []
            
            # 1. Long duration but very low traffic (trying to stay under radar)
            if profile['duration'] > 43200 and profile['count'] < 20:  # > 12 hours with < 20 attempts
                evidence.append("Long duration with very low traffic volume (evasion technique)")
                
            # 2. Targeting specific sensitive services
            sensitive_service_targeting = False
            admin_ports = [22, 3389, 8080, 8443]
            db_ports = [1433, 3306, 5432, 27017, 6379]
            
            if hasattr(profile, 'ports_targeted') and profile['ports_targeted']:
                targeted_ports = [port for port, _ in profile['ports_targeted']]
                
                # Check for admin access attempts
                admin_port_targeting = [port for port in targeted_ports if port in admin_ports]
                if admin_port_targeting:
                    evidence.append(f"Targeting admin services: {admin_port_targeting}")
                    sensitive_service_targeting = True
                    
                # Check for database access attempts
                db_port_targeting = [port for port in targeted_ports if port in db_ports]
                if db_port_targeting:
                    evidence.append(f"Targeting database services: {db_port_targeting}")
                    sensitive_service_targeting = True
            
            # 3. Low volume & sensitive targeting & medium/high duration = APT candidate
            if (sensitive_service_targeting and 
                profile['count'] < 50 and 
                profile['duration'] > 3600):  # > 1 hour
                apt_candidates.append({
                    'source_ip': ip,
                    'evidence': evidence,
                    'first_seen': profile['first_seen'],
                    'last_seen': profile['last_seen'],
                    'duration': profile['duration'],
                    'confidence': 'Medium'
                })
                
        return apt_candidates
    
    def generate_report(self) -> Dict:
        """
        Generate a comprehensive report of analysis results.
        
        Returns:
            Dictionary containing all analysis results
        """
        if not hasattr(self, 'summary') or not self.summary:
            return {'error': 'No analysis results available'}
            
        # Create report structure
        report = {
            'summary': self.summary,
            'attack_groups': self.attack_groups,
            'sophistication_breakdown': {},
            'apt_candidates': self.identify_apt_patterns(),
            'top_attackers': []
        }
        
        # Add sophistication breakdown with examples
        for level in ['LOW', 'MEDIUM', 'HIGH', 'APT']:
            level_attackers = []
            for ip, profile in self.attackers.items():
                if profile['sophistication_level'] == level:
                    level_attackers.append({
                        'ip': ip,
                        'count': profile['count'],
                        'duration': profile['duration'],
                        'targets': len(profile['targets']),
                        'reasons': profile.get('classification_reasons', [])
                    })
            
            # Sort by count and take top 5
            sorted_attackers = sorted(level_attackers, key=lambda x: x['count'], reverse=True)[:5]
            
            report['sophistication_breakdown'][level] = {
                'count': len(level_attackers),
                'description': self.SOPHISTICATION_LEVELS[level],
                'examples': sorted_attackers
            }
            
        # Add top attackers overall (by attempt count)
        top_attackers = []
        for ip, profile in self.attackers.items():
            top_attackers.append({
                'ip': ip,
                'count': profile['count'],
                'sophistication': profile['sophistication_level'],
                'duration': profile['duration'],
                'targets': len(profile['targets'])
            })
        
        report['top_attackers'] = sorted(top_attackers, key=lambda x: x['count'], reverse=True)[:10]
        
        return report
    
    def print_summary(self) -> None:
        """Print a summary of the analysis results to the console."""
        if not hasattr(self, 'summary') or not self.summary:
            print("No analysis results available")
            return
            
        print("\n" + "="*80)
        print(" SECURITY LOG ANALYSIS SUMMARY ")
        print("="*80)
        
        s = self.summary
        print(f"\nAnalyzed {s['total_logs']} log entries spanning {s['time_span']}")
        print(f"Found {s['unique_sources']} unique source IPs targeting {s['unique_destinations']} destinations")
        
        print("\nAttack Sophistication Breakdown:")
        for level, count in s['sophistication_counts'].items():
            print(f"  - {level}: {count} attackers ({count/s['unique_sources']*100:.1f}%)")
            
        print("\nMost Targeted Ports:")
        for port, count in s['most_targeted_ports']:
            service = self.COMMON_PORTS.get(port, "Unknown")
            print(f"  - Port {port} ({service}): {count} attempts")
            
        print("\nAPT Candidates:")
        apt_candidates = self.identify_apt_patterns()
        if apt_candidates:
            for candidate in apt_candidates:
                print(f"  - {candidate['source_ip']} (Confidence: {candidate['confidence']})")
                for evidence in candidate['evidence']:
                    print(f"    * {evidence}")
        else:
            print("  No APT patterns detected")
            
        print("\nTop Attackers:")
        top_attackers = sorted(self.attackers.items(), key=lambda x: x[1]['count'], reverse=True)[:5]
        for ip, profile in top_attackers:
            print(f"  - {ip} ({profile['sophistication_level']}): {profile['count']} attempts across {profile['target_count']} targets")
            
        print("\n" + "="*80)
        
    def save_results(self, output_file: str) -> bool:
        """
        Save analysis results to a JSON file.
        
        Args:
            output_file: Path where to save the results
            
        Returns:
            bool: True if saving was successful, False otherwise
        """
        try:
            # Generate report
            report = self.generate_report()
            
            # Convert datetime objects to strings for JSON serialization
            report_serializable = self._make_json_serializable(report)
            
            # Save to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_serializable, f, indent=2)
                
            print(f"Analysis results saved to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error saving results: {e}")
            return False
            
    def _make_json_serializable(self, obj):
        """Convert datetime and other non-serializable objects for JSON output."""
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, (datetime, np.datetime64)):
            return str(obj)
        elif isinstance(obj, (pd.Timedelta, timedelta)):
            # Convert timedeltas to string representation
            return str(obj)
        elif isinstance(obj, np.int64):
            return int(obj)
        elif isinstance(obj, np.float64):
            return float(obj)
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, Counter):
            return dict(obj)
        else:
            return obj


def find_newest_json_file(directory="../data"):
    """
    Find the newest JSON file in the specified directory.
    
    Args:
        directory: Directory to search for JSON files
        
    Returns:
        str: Path to the newest JSON file, or None if no JSON files found
    """
    try:
        # Make sure directory exists
        if not os.path.exists(directory):
            print(f"Warning: Directory {directory} does not exist")
            return None
            
        # Find all JSON files in directory
        json_files = [
            os.path.join(directory, f) for f in os.listdir(directory)
            if f.lower().endswith('.json')
        ]
        
        if not json_files:
            print(f"Warning: No JSON files found in {directory}")
            return None
            
        # Find the newest file
        newest_file = max(json_files, key=os.path.getmtime)
        return newest_file
        
    except Exception as e:
        print(f"Error finding newest JSON file: {e}")
        return None

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Enhanced analysis of SecurityOnion log data with attack pattern detection"
    )
    
    parser.add_argument(
        "input_file",
        help="Path to JSON log file exported from SecurityOnion (if not specified, uses newest JSON in ../data)",
        nargs='?',
        default=None
    )
    
    parser.add_argument(
        "--output",
        help="Path to save analysis results (JSON format)",
        default=None
    )
    
    parser.add_argument(
        "--verbose",
        help="Enable verbose output",
        action="store_true"
    )
    
    return parser.parse_args()


def main():
    """Main execution function."""
    args = parse_arguments()
    
    # If no input file specified, use the newest JSON in ../data
    input_file = args.input_file
    if input_file is None:
        input_file = find_newest_json_file()
        if input_file is None:
            print("Error: No input file specified and no JSON files found in ../data")
            return 1
        print(f"Using newest JSON file: {input_file}")
    
    # Check if input file exists
    if not os.path.isfile(input_file):
        print(f"Error: Input file not found: {input_file}")
        return 1
    
    # Create analyzer
    analyzer = SecurityLogAnalyzer(verbose=args.verbose)
    
    # Load and analyze data
    if not analyzer.load_data(input_file):
        return 1
    
    analyzer.preprocess_data()
    analyzer.analyze_attack_patterns()
    
    # Print summary to console
    analyzer.print_summary()
    
    # Save results if output file specified
    if args.output:
        analyzer.save_results(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
