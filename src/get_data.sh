#! /bin/bash


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


PATTERN="observer.type:firewall"

for DAY in $(seqdate 2025-03-25 2025-03-28); do 
    #echo "$DAY"
    python get_data.py --oql \
        "$PATTERN @timestamp:>=${DAY}T00:00:00Z @timestamp:<=${DAY}T23:59:59Z" \
        --full-extract --format json \
        --export ../data/data_log_firewall_${DAY}.json
done
