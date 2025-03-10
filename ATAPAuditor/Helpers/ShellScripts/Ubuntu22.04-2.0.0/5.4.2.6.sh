#!/usr/bin/env bash

source /root/.bashrc
current_umask=$(umask)

if [[ "$current_umask" == "0027" ]]; then
	exit 0
else
	exit 1
fi
