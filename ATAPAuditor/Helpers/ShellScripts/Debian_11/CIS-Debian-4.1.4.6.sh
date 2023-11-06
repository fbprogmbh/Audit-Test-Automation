#!/usr/bin/env bash
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root