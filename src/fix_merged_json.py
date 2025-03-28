#!/usr/bin/env python
"""
Utility script to fix incorrectly merged JSON arrays in SecurityOnion log files.

This script handles the specific case where multiple JSON arrays have been 
concatenated with ][ instead of being properly merged with a comma.

Usage:
    python fix_merged_json.py input_file.json output_file.json
"""

import os
import sys
import json
import re


def fix_merged_arrays(input_file, output_file):
    """
    Fix incorrectly merged JSON arrays in a file.
    
    Args:
        input_file: Path to the corrupted JSON file
        output_file: Path where to save the fixed JSON
        
    Returns:
        bool: True if fixing was successful, False otherwise
    """
    try:
        print(f"Reading file: {input_file}")
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check if the file contains the pattern of multiple arrays (][)
        if '][' not in content:
            print("No incorrectly merged arrays found in the file")
            return False
            
        # Method 1: Replace ][ with a comma to create a single valid array
        fixed_content = content.replace('][', ',')
        
        # Try to parse the fixed content
        try:
            json_data = json.loads(fixed_content)
            print(f"Successfully merged multiple arrays into a single array")
            print(f"Total items in the fixed array: {len(json_data)}")
            
            # Write the fixed JSON to the output file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f)
                
            print(f"Fixed JSON saved to: {output_file}")
            return True
            
        except json.JSONDecodeError as e:
            print(f"Simple replacement failed: {e}")
            
            # Method 2: Try more advanced fixing
            print("Attempting more advanced fixing...")
            
            # Fix potential issues with the start/end of the content
            if not content.startswith('['):
                content = '[' + content
            if not content.endswith(']'):
                content = content + ']'
                
            # Replace all occurrences of ][ with commas
            fixed_content = re.sub(r'\]\s*\[', ',', content)
            
            try:
                json_data = json.loads(fixed_content)
                print(f"Advanced fixing successful")
                print(f"Total items in the fixed array: {len(json_data)}")
                
                # Write the fixed JSON to the output file
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f)
                    
                print(f"Fixed JSON saved to: {output_file}")
                return True
                
            except json.JSONDecodeError as e2:
                print(f"Advanced fixing failed: {e2}")
                
                # Method 3: Extract and combine individual arrays
                print("Attempting to extract and combine individual arrays...")
                
                # Find all JSON arrays in the content
                array_pattern = r'\[(?:[^[\]]*|\[(?:[^[\]]*|\[[^[\]]*\])*\])*\]'
                arrays = re.findall(array_pattern, content)
                
                if arrays:
                    print(f"Found {len(arrays)} potential JSON arrays")
                    
                    # Try to parse each array and combine valid ones
                    combined_data = []
                    for i, array in enumerate(arrays):
                        try:
                            array_data = json.loads(array)
                            if isinstance(array_data, list):
                                combined_data.extend(array_data)
                                print(f"Successfully parsed array {i+1} with {len(array_data)} items")
                        except json.JSONDecodeError:
                            print(f"Skipping invalid array {i+1}")
                            
                    if combined_data:
                        print(f"Combined {len(combined_data)} items from valid arrays")
                        
                        # Write the combined data to the output file
                        with open(output_file, 'w', encoding='utf-8') as f:
                            json.dump(combined_data, f)
                            
                        print(f"Fixed JSON saved to: {output_file}")
                        return True
                
                print("All fixing methods failed")
                return False
                
    except Exception as e:
        print(f"Error: {e}")
        return False


def main():
    """Main execution function."""
    if len(sys.argv) != 3:
        print("Usage: python fix_merged_json.py input_file.json output_file.json")
        return 1
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Check if input file exists
    if not os.path.isfile(input_file):
        print(f"Error: Input file not found: {input_file}")
        return 1
        
    # Fix the merged arrays
    success = fix_merged_arrays(input_file, output_file)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
