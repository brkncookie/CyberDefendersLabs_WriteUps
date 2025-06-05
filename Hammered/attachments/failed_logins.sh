#!/bin/bash

# Check if input file is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ip_list_file>"
    exit 1
fi

ip_list="$1"
auth_log="./auth.log"

# Check if auth.log exists
if [ ! -f "$auth_log" ]; then
    echo "Error: $auth_log not found!"
    exit 1
fi

# Process each IP in the list
while IFS= read -r ip; do
    # Skip empty lines
    if [ -z "$ip" ]; then
        continue
    fi

    # Count failed attempts for this IP
    count=$(grep "Failed password" "$auth_log" | grep -F "$ip" | wc -l)
    echo "$ip: $count failed attempts"
done < "$ip_list"
