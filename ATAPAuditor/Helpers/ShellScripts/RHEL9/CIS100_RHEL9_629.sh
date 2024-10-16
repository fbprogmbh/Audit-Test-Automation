#!/usr/bin/env bash
{
    awk -F: '($3 == 0) { print $1 }' /etc/passwd
}