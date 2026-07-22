#!/usr/bin/env bash
{
     /usr/sbin/useradd -D | grep INACTIVE | cut -d '=' -f 2
}