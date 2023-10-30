#!/bin/bash
awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(
    awk
    '/^\s*UID_MIN/{print $2}' /etc/login.defs
)"' &&
$7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print}' /etc/passwd

awk -F: '($1!~/(root|^\+)/ && $3<'"$(
    awk '/^\s*UID_MIN/{print $2}'
    /etc/login.defs
)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' |
    awk '($2!~/LK?/) {print $1}'
