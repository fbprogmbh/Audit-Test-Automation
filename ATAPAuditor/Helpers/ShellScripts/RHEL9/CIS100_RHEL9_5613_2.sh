#!/usr/bin/env bash
{
    for var in $(grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f6)
    do
        if [ $var -le 7 ]; then
            echo "FAIL"
        fi
    done
}