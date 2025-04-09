#!/bin/bash

# Function to generate a sequence of dates between two given dates
seqdate() {
    local start="$1"
    local end="$2"

    if [[ -z "$start" || -z "$end" ]]; then
        echo "Usage: seqdate YYYY-MM-DD YYYY-MM-DD"
        return 1
    fi

    local current=$(date -jf "%Y-%m-%d" "$start" +%s)
    local end_ts=$(date -jf "%Y-%m-%d" "$end" +%s)

    while [[ "$current" -le "$end_ts" ]]; do
        date -r "$current" "+%Y-%m-%d"
        current=$(( current + 86400 ))
    done
}

# Process each day in the specified date range
for DAY in $(seqdate 2025-03-28 2025-03-29); do
    FILE=../data/data_log_web_${DAY}.json
    tmpfile=$(mktemp ../data/.export_web_${DAY}.XXXXXX)
    
    echo "Extracting web logs for ${DAY}"
    
    # Use the refined version of the script with improved filtering
    python get_web_data.py \
        --apache --php \
        --from-date ${DAY} --to-date ${DAY} \
        --full-extract \
        --format json \
        --debug \
        --export ${tmpfile}
    
    # Check if any logs were found
    if [ -s "$tmpfile" ]; then
        # Fix potentially corrupted JSON arrays
        ./fix_merged_json.py "$tmpfile" "$FILE"
        echo "Web logs saved to $FILE"
    else
        echo "No web logs found for $DAY"
        echo "[]" > "$FILE"  # Create empty JSON array
    fi
    
    rm "$tmpfile"
    echo "Completed extraction for ${DAY}"
done
