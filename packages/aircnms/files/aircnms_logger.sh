#!/bin/sh

LOG_DIR="/overlay/logs"
LOG_FILE="$LOG_DIR/aircnms.log"
FILTER='QM|qm|SM|sm|DM|dm|CM|cm'

# Ensure log directory and file exist
[ -d "$LOG_DIR" ] || mkdir -p "$LOG_DIR"
[ -f "$LOG_FILE" ] || touch "$LOG_FILE"

# Function to check file size and rotate if needed
check_log_size() {
    FILE_SIZE=$(wc -c < "$LOG_FILE")
    MAX_SIZE=1500   # Use 1500000 for 1.5 MB in production

    if [ "$FILE_SIZE" -gt "$MAX_SIZE" ]; then
        echo "$(date): Log file exceeded $MAX_SIZE bytes, rotating..." >> "$LOG_FILE"
        : > "$LOG_FILE"   # Truncate the file (clears content but keeps same inode)
    fi
}

echo "aircnms_logger started, writing to $LOG_FILE"

# Run logread in a controlled, restartable loop
while true; do
    logread -f 2>/dev/null | grep -Ei "$FILTER" >> "$LOG_FILE" &
    LOG_PID=$!

    while kill -0 "$LOG_PID" 2>/dev/null; do
        check_log_size
        sleep 5
    done

    echo "$(date): logread stopped, restarting..." >> "$LOG_FILE"
    sleep 2
done

