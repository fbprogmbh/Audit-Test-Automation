#!/usr/bin/env bash
{
    grep PASS_MAX_DAYS /etc/login.defs | cut -d ' ' -f 2
}