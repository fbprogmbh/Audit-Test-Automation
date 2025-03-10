#!/usr/bin/env bash

pmask="0133"
maxperm="$(printf '%o' $((0777 & ~$pmask)))"

find -L /etc/ssh -type f 2>/dev/null | while IFS= read -r file; do
	if ssh-keygen -lf "$file" &>/dev/null && file "$file" | grep -qi 'OpenSSH.*public key'; then
		read -r mode owner group < <(stat -Lc '%#a %U %G' "$file")
		[ $((mode & pmask)) -gt 0 ] && exit 1
		[ "$owner" != "root" ] && exit 1
		[ "$group" != "root" ] && exit 1
	fi
done
