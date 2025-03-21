#!/bin/bash

root_gid=$(getent group root | cut -d: -f3)

if [[ "$root_gid" != "0" ]]; then
    echo "Error: The root group does not have GID 0."
    exit 1
fi

other_groups=$(getent group | awk -F: '$3 == 0 && $1 != "root" {print $1}')

if [[ -n "$other_groups" ]]; then
    echo "Error: The following groups also have GID 0: $other_groups"
    exit 1
fi

exit 0
