#!/bin/bash

# Fix 1: Add missing sys/time.h include
sed -i '9a #include <sys/time.h>' src/libs/unixcomm/inc/unixcomm.h

# Fix 2: Add topic_len field to unixcomm_request_t structure (after data_size field)
sed -i '/uint32_t data_size;/a \    uint32_t topic_len;              // Topic length' src/libs/unixcomm/inc/unixcomm.h

# Fix 3: Add topic field to unixcomm_message_t structure (after data field)
sed -i '/void \*data;/a \    char *topic;                    // Topic string' src/libs/unixcomm/inc/unixcomm.h

echo "Fixes applied successfully!"
