#!/bin/bash
while read -r name; do
  if [ "$(<${name/dev/sys\/block}/removable)" -eq "1" ]; then 
    mount | grep "$name"
  fi
done < <(awk '/^\/dev\/sd/ {sub(/[0-9]+$/,"",$1); print $1}' /proc/mounts | uniq)
