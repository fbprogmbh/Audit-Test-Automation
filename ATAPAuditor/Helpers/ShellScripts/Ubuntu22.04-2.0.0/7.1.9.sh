#!/bin/bash

file="/etc/shells"

if [[ ! -e "$file" ]]; then
    exit 0
fi

mode=$(stat -c "%a" "$file")
uid=$(stat -c "%u" "$file")
gid=$(stat -c "%g" "$file")

if [[ "$mode" -le 644 && "$uid" -eq 0 && "$gid" -eq 0 ]]; then
    exit 0
else
    exit 1
fi

