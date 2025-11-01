#!/bin/sh

LOGROTATE_CONF="/etc/logrotate.conf"
INTERVAL=5

while true; do
    /usr/sbin/logrotate "$LOGROTATE_CONF"
    sleep "$INTERVAL"
done


