#!/bin/bash

root_password=$(getent shadow root | cut -d: -f2)

if [[ "$root_password" == "*" || "$root_password" == "!" || -z "$root_password" ]]; then
    exit 1
fi

exit 0

