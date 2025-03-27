#!/usr/bin/env python

#import os
import re
import pandas as pd
from pandas import DataFrame


def read_logfile(filename):
    with open(filename, "r", encoding="utf-8") as f:
        line = f.readlines()
    df: DataFrame = pd.DataFrame(line, columns=["line"])
    return df

import pandas as pd
import re

def extract_ip_pairs(df, column_name):
    """
    Extracts the first two IP addresses (IPv4 or IPv6) from a specified column.
    The first IP is assumed to be the attacker, the second is the victim.

    Parameters:
        df (pd.DataFrame): The input DataFrame containing text data.
        column_name (str): The name of the column to search for IP addresses.

    Returns:
        pd.DataFrame: A copy of the original DataFrame with 'attacker_ip' and 'victim_ip' columns.
    """
    # Pattern to match IPv4 and IPv6 addresses - simplified for better matching
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    # Extract IPs and assign to new columns
    def extract_ips(text):
        matches = re.findall(ip_pattern, text)
        attacker = matches[0] if len(matches) > 0 else None
        victim = matches[1] if len(matches) > 1 else None
        return pd.Series([attacker, victim])

    # Create a new dataframe with the extracted IP addresses
    result_df = df.copy()
    result_df[['attacker_ip', 'victim_ip']] = df[column_name].apply(extract_ips)

    return result_df

logfile_name = '../data/data_log_firewall_48h.txt'
df_logs = read_logfile(logfile_name)

print(df_logs.head())
print(f"\nLogfile '{logfile_name}' contains {len(df_logs)} lines")

# extract IP for attacker and victim
df_ip_addrs = extract_ip_pairs(df_logs, "line")
print(df_ip_addrs.head())  # Added parentheses to call the method

# Print a summary of found IP addresses
# TODO: add date and reason
print("\nSample of attacker and victim IPs:")
print(df_ip_addrs[['attacker_ip', 'victim_ip']].head())

