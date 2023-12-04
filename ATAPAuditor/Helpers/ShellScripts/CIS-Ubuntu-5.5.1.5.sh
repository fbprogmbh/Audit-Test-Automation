#!/bin/bash
awk -F : '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; do [ "$(date --date="$(chage --list "$usr" | grep '^Last password change' | cut -d: -f2)" +%s)" -gt "$(date "+%s")" ] && echo "user: $usr password change date: $(chage --list "$usr" | grep '^Last password change' | cut -d: -f2)"; done
