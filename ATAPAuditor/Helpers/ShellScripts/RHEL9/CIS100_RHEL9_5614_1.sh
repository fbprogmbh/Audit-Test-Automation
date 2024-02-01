#!/usr/bin/env bash
{
    useradd -D | grep INACTIVE | cut -d '=' -f 2
}