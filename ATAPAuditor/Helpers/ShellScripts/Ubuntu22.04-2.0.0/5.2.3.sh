#!/usr/bin/env bash

PATTERN="^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$"
FILES='/etc/sudoers*'

if grep -rPsi "$PATTERN" $FILES >/dev/null 2>&1; then
	exit 0
else
	exit 1
fi
