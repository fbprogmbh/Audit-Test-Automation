#!/usr/bin/env bash
l_output="" l_output2="" l_output3="" l_dl="" # Unset output variables
l_mname="usb-storage"                         # set module name
l_mtype="drivers"                             # set module type
l_searchloc="/lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf"
#replaced in original script to avoid globstar operator
l_mpath=$(find /lib/modules/ -type d -name $l_mtype)
l_mpname="$(tr '-' '_' <<<"$l_mname")"
l_mndir="$(tr '-' '/' <<<"$l_mname")"
module_loadable_chk() {
	# Check if the module is currently loadable
	l_loadable="$(modprobe -n -v "$l_mname")"
	[ "$(wc -l <<<"$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- "(^\h*install|\b$l_mname)\b" <<<"$l_loadable")"
	if grep -Pq -- '^\h*install \/bin\/(true|false)' <<<"$l_loadable"; then
		l_output="$l_output\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
	else
		l_output2="$l_output2\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
	fi
}
module_loaded_chk() {
	# Check if the module is currently loaded
	if ! lsmod | grep "$l_mname" >/dev/null 2>&1; then
		l_output="$l_output\n - module: \"$l_mname\" is not loaded"
	else
		l_output2="$l_output2\n - module: \"$l_mname\" is loaded"
	fi
}
module_deny_chk() {
	# Check if the module is deny listed
	l_dl="y"
	if modprobe --showconfig | grep -Pq -- '^\h*blacklist\h+'"$l_mpname"'\b'; then
		l_output="$l_output\n - module: \"$l_mname\" is deny listed in: \"$(grep -Pls -- "^\h*blacklist\h+$l_mname\b" $l_searchloc)\""
	else
		l_output2="$l_output2\n - module: \"$l_mname\" is not deny listed"
	fi
}
# Check if the module exists on the system
for l_mdir in $l_mpath; do
	if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
		l_output3="$l_output3\n - \"$l_mdir\""
		[ "$l_dl" != "y" ] && module_deny_chk
		if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
			module_loadable_chk
			module_loaded_chk
		fi
	else
		l_output="$l_output\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\""
	fi
done
# Report results. If no failures output in l_output2, we pass
[ -n "$l_output3" ] && echo -e "\n\n -- INFO --\n - module: \"$l_mname\" exists in:$l_output3"
if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
	exit 0
else
	echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
	[ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
	exit 1
fi
