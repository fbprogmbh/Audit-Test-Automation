#!/usr/bin/env bash

test_failed=0
for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
	for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
		if grep -qr "${PRIVILEGED}" /etc/audit/rules.d; then
			printf "OK: '${PRIVILEGED}' found in on-disk configuration.\n"
		else
			printf "ERROR: '${PRIVILEGED}' not found in on-disk configuration.\n"
			test_failed=1
		fi
	done
done

RUNNING=$(auditctl -l)
if [ -n "${RUNNING}" ]; then
	for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
		for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
			if printf -- "${RUNNING}" | grep -q "${PRIVILEGED}"; then
				printf "OK: '${PRIVILEGED}' found in running configuration.\n"
			else
				printf "ERROR: '${PRIVILEGED}' not found in running configuration.\n"
				test_failed=1
			fi
		done
	done
else
	printf "ERROR: No rules found in running configuration.\n"
	test_failed=1
fi

# Setze den Exit-Code basierend auf dem Test-Status
if [ "$test_failed" -eq 0 ]; then
	exit 0
else
	echo "Some checks failed."
	exit 1
fi
