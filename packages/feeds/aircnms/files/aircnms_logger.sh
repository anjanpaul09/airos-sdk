#!/bin/sh

LOGDIR="/overlay/log"
LOGFILE="$LOGDIR/aircnms.log"
MAXSIZE=15360   # 15 KB

mkdir -p "$LOGDIR"

get_size() {
    if [ -f "$1" ]; then
        wc -c < "$1"
    else
        echo 0
    fi
}

rotate_log() {
    SIZE=$(get_size "$LOGFILE")
    if [ "$SIZE" -ge "$MAXSIZE" ]; then
        : > "$LOGFILE"   # just truncate, no backup copy
    fi
}

PIPE="/tmp/aircnms_logpipe"
[ -p "$PIPE" ] || mkfifo "$PIPE"

logread -f | grep -E 'QM|SM|CM|DM' > "$PIPE" &
exec < "$PIPE"

while read -r line; do
    echo "$line" >> "$LOGFILE"
    rotate_log
done

