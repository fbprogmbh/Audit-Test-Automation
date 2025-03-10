#!/usr/bin/env bash

socket_installed=$(systemctl list-unit-files | grep -q 'systemd-journal-remote.socket' && echo true || echo false)
service_installed=$(systemctl list-unit-files | grep -q 'systemd-journal-remote.service' && echo true || echo false)

if [[ "$socket_installed" == "false" && "$service_installed" == "false" ]]; then
	exit 0 # True if neither is installed
elif [[ "$socket_installed" == "true" && "$(systemctl is-active systemd-journal-remote.socket)" =~ ^(inactive|failed)$ ]] &&
	[[ "$service_installed" == "true" && "$(systemctl is-active systemd-journal-remote.service)" =~ ^(inactive|failed)$ ]]; then
	exit 0 # True if both are not active (including failed)
else
	exit 1 # False otherwise
fi
