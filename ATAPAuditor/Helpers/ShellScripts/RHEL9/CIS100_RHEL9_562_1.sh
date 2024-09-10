#!/usr/bin/env bash
{
    awk -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) && $7!~/^(\/usr)?\/sbin\/nologin$/) { print $1 }' /etc/passwd
}