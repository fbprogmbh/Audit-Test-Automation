#!/usr/bin/env bash
{
    [ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec stat -Lc "%n %U" {} +
}