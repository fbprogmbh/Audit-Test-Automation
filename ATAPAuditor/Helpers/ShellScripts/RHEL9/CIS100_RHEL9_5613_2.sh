#!/usr/bin/env bash
{
    awk -F: '(/^[^:]+:[^!*]/ && `$6<7){print `$1 " " `$6}' /etc/shadow
}