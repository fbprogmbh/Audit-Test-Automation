#!/usr/bin/env bash
{
    grep PASS_WARN_AGE /etc/login.defs | cut -d ' ' -f 2
}