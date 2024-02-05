#!/usr/bin/env bash
{
    grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6
}