#!/usr/bin/env bash
{
    grep PASS_MIN_DAYS /etc/login.defs | cut -d ' ' -f 2
}