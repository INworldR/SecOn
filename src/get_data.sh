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


#PATTERN="host.name:secon observer.type:firewall"
PATTERN="observer.type:firewall"

for DAY in $(seqdate 2025-05-07 2025-05-08); do
    FILE=../data/data_log_firewall_${DAY}.json
    #echo -n '' >$FILE
    tmpfile=$(mktemp ../data/.export_${DAY}.XXXXXX)
    for HOUR in {0..23}; do
        HOUR_PADDED=$(printf "%02d" $HOUR)
        tmpfile_hour=$(mktemp ../data/.export_${DAY}_${HOUR_PADDED}.XXXXXX)
        echo "timestamp:>=${DAY}T${HOUR_PADDED}:00:00Z @timestamp:<=${DAY}T${HOUR_PADDED}:59:59Z"
        python get_data.py --oql \
            "$PATTERN @timestamp:>=${DAY}T${HOUR_PADDED}:00:00Z @timestamp:<=${DAY}T${HOUR_PADDED}:59:59Z" \
            --full-extract --format json \
            --export "$tmpfile_hour"
        cat "$tmpfile_hour" >>"$tmpfile"
        rm "$tmpfile_hour"
    done
    ./fix_merged_json.py "$tmpfile" "$FILE"
    rm "$tmpfile"
done
