#!/usr/bin/env bash

regex_pattern="^\s*ForwardToSyslog\s*=\s*no"
config_files=("/etc/systemd/journald.conf" "/etc/systemd/journald.conf.d/*")

for config_file in "${config_files[@]}"; do
	for file in $config_file; do
		if [[ -f "$file" ]]; then
			if grep -qE "$regex_pattern" "$file"; then
				exit 0
			fi
		fi
	done
done

exit 1
