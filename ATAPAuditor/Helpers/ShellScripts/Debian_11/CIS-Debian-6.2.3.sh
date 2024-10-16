#!/usr/bin/env bash
a_passwd_group_gid=("$(awk -F: '{print $4}' /etc/passwd | sort -u)")
a_group_gid=("$(awk -F: '{print $3}' /etc/group | sort -u)")
a_passwd_group_diff=("$(printf '%s\n' "${a_group_gid[@]}" "${a_passwd_group_gid[@]}" | sort | uniq -u)")
while IFS= read -r l_gid; do
	awk -F: '($4 == '"$l_gid"') {print " - User: \"" $1 "\" has GID: \"" $4 "\" which does not exist in /etc/group" }' /etc/passwd
	exit 1
done < <(printf '%s\n' "${a_passwd_group_gid[@]}" "${a_passwd_group_diff[@]}" | sort | uniq -D | uniq)
exit 0
