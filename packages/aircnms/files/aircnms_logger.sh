#!/bin/sh

# Configuration
LOGDIR="/overlay/log"
LOGFILE="$LOGDIR/aircnms.log"
PIPE="/tmp/aircnms_logpipe"
CONFIG_FILE="/etc/config/aircnms"
PIDFILE="/tmp/aircnms_logger.pid"
LOG_PATTERN='QM|SM|CM|DM'

# Global variables
MAX_LOG_SIZE=""
LOGREAD_PID=""
SHUTDOWN_FLAG=false

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Error handling
handle_error() {
    log_message "ERROR: $1"
    cleanup_and_exit 1
}

# Cleanup function
cleanup_and_exit() {
    local exit_code=${1:-0}
    SHUTDOWN_FLAG=true
    
    log_message "Shutting down aircnms logger..."
    
    # Kill logread process if running
    if [ -n "$LOGREAD_PID" ] && kill -0 "$LOGREAD_PID" 2>/dev/null; then
        kill "$LOGREAD_PID" 2>/dev/null
        wait "$LOGREAD_PID" 2>/dev/null
    fi
    
    
    # Clean up pipe
    [ -p "$PIPE" ] && rm -f "$PIPE"
    
    # Remove PID file
    [ -f "$PIDFILE" ] && rm -f "$PIDFILE"
    
    log_message "Cleanup completed"
    exit "$exit_code"
}

# Signal handlers
trap 'cleanup_and_exit 0' TERM INT

# Get log size from UCI configuration
get_max_log_size() {
    local size
    size=$(uci get aircnms.@aircnms[0].log_size 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$size" ] && [ "$size" -gt 0 ]; then
        echo "$size"
    else
        log_message "WARNING: Could not get log_size from UCI, using default 15360"
        echo "15360"
    fi
}

# Get file size in bytes
get_file_size() {
    if [ -f "$1" ]; then
        wc -c < "$1" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Rotate log file if it exceeds max size
rotate_log() {
    local current_size
    current_size=$(get_file_size "$LOGFILE")
    
    if [ "$current_size" -ge "$MAX_LOG_SIZE" ]; then
        log_message "Log file size ($current_size bytes) exceeds limit ($MAX_LOG_SIZE bytes), rotating..."
        : > "$LOGFILE"
        log_message "Log file rotated successfully"
    fi
}

# Start logread process
start_logread() {
    # Ensure pipe exists
    [ -p "$PIPE" ] || mkfifo "$PIPE"
    
    # Start logread in background
    logread -f | grep -E "$LOG_PATTERN" > "$PIPE" &
    LOGREAD_PID=$!
    
    if ! kill -0 "$LOGREAD_PID" 2>/dev/null; then
        handle_error "Failed to start logread process"
    fi
    
    log_message "Logread process started with PID $LOGREAD_PID"
}

# Check and update configuration if changed
check_config_change() {
    local new_max_size
    new_max_size=$(get_max_log_size)
    
    if [ "$new_max_size" != "$MAX_LOG_SIZE" ]; then
        log_message "Log size changed from $MAX_LOG_SIZE to $new_max_size bytes"
        MAX_LOG_SIZE="$new_max_size"
        
        # Check if current log needs rotation with new size
        rotate_log
        return 0  # Configuration changed
    fi
    
    return 1  # No change
}

# Main logging loop
main_logging_loop() {
    local line
    local config_check_counter=0
    
    while [ "$SHUTDOWN_FLAG" = false ]; do
        # Check configuration every 5 iterations (roughly every 5 seconds)
        config_check_counter=$((config_check_counter + 1))
        if [ $config_check_counter -ge 5 ]; then
            if check_config_change; then
                log_message "Configuration updated successfully"
            fi
            config_check_counter=0
        fi
        
        # Read line with timeout to allow checking configuration
        if read -r -t 1 line 2>/dev/null; then
            echo "$line" >> "$LOGFILE"
            rotate_log
        fi
    done
}

# Initialize the logger
initialize() {
    log_message "Initializing aircnms logger..."
    
    # Create log directory
    mkdir -p "$LOGDIR" || handle_error "Failed to create log directory: $LOGDIR"
    
    # Get initial configuration
    MAX_LOG_SIZE=$(get_max_log_size)
    log_message "Maximum log size set to: $MAX_LOG_SIZE bytes"
    
    # Check if already running
    if [ -f "$PIDFILE" ]; then
        local old_pid
        old_pid=$(cat "$PIDFILE" 2>/dev/null)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            log_message "Another instance is already running (PID: $old_pid)"
            exit 1
        else
            rm -f "$PIDFILE"
        fi
    fi
    
    # Write PID file
    echo $$ > "$PIDFILE"
    
    # Start logread process
    start_logread
    
    log_message "Logger initialized successfully"
    log_message "Configuration will be checked every ~5 seconds"
    log_message "To test: uci set aircnms.@aircnms[0].log_size='<new_value>' && uci commit aircnms"
}

# Main execution
main() {
    # Redirect stdin from pipe
    exec < "$PIPE"
    
    # Initialize
    initialize
    
    # Start main logging loop
    main_logging_loop
    
    # Cleanup on exit
    cleanup_and_exit 0
}

# Run main function
main "$@"

