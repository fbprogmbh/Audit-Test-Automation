#!/usr/bin/env bash

tmout=$(grep 'typeset -xr TMOUT=900' -- /etc/bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null)
if [[ -n "$tmout" ]]; then
	exit 0
else
	exit 1
fi
