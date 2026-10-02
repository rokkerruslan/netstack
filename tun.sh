#!/usr/bin/env bash
# Create or delete a TUN interface, optionally in its own network namespace.
#
# Usage:
#   ./tun.sh up     [--netns NS] [name] [cidr]   # default: tun0 10.0.0.1/24
#   ./tun.sh down   [--netns NS] [name]
#   ./tun.sh status [--netns NS] [name]
#   ./tun.sh exec   NS cmd [args...]             # run cmd in NS as your user
#
# With --netns the program that reads the TUN must also run in NS
# (use exec), because the kernel looks up the interface by name there.
#
# Environment:
#   TUN_USER  owner of the interface (default: the user who ran sudo).

set -euo pipefail

args=("$@")
owner="${TUN_USER:-${SUDO_USER:-$USER}}"

usage() {
	echo "usage: $0 {up|down|status} [--netns NS] [name] [cidr]" >&2
	echo "       $0 exec NS cmd [args...]" >&2
	exit 1
}

need_root() {
	if [[ $EUID -ne 0 ]]; then
		exec sudo --preserve-env=TUN_USER "$0" "${args[@]}"
	fi
}

cmd="${1:-}"
shift || true

if [[ $cmd == exec ]]; then
	[[ $# -ge 2 ]] || usage
	ns="$1"
	shift
	# sudo resets PATH and HOME, so pass them explicitly.
	# Drop root back to the user inside the namespace.
	exec sudo --preserve-env ip netns exec "$ns" \
		setpriv --reuid="$(id -u "$owner")" --regid="$(id -g "$owner")" --init-groups -- \
		env "PATH=$PATH" "HOME=$HOME" "$@"
fi

ns=""
if [[ ${1:-} == --netns ]]; then
	[[ -n ${2:-} ]] || usage
	ns="$2"
	shift 2
fi
name="${1:-tun0}"
cidr="${2:-10.0.0.1/24}"

# in_ns runs a command in the namespace, if one is set.
in_ns() {
	if [[ -n $ns ]]; then
		ip netns exec "$ns" "$@"
	else
		"$@"
	fi
}

exists() {
	in_ns ip link show dev "$name" &>/dev/null
}

case "$cmd" in
up)
	need_root
	if [[ -n $ns ]]; then
		if ip netns list | grep -qw "$ns"; then
			echo "netns $ns already exists" >&2
			exit 1
		fi
		ip netns add "$ns"
		in_ns ip link set dev lo up
		# Let normal users listen on ports below 1024 in this namespace.
		in_ns sysctl -qw net.ipv4.ip_unprivileged_port_start=0
	elif exists; then
		echo "interface $name already exists" >&2
		exit 1
	fi
	in_ns ip tuntap add dev "$name" mode tun user "$owner"
	# Turn off multicast and IPv6 to avoid background traffic.
	# Do it before the interface is up.
	in_ns ip link set dev "$name" multicast off
	in_ns sysctl -qw "net.ipv6.conf.$name.disable_ipv6=1"
	in_ns ip addr add "$cidr" dev "$name"
	in_ns ip link set dev "$name" up
	echo "created $name ($cidr), owner $owner${ns:+, netns $ns}"
	;;
down)
	need_root
	if [[ -n $ns ]]; then
		# Deleting the namespace also deletes its interfaces.
		ip netns delete "$ns"
		echo "deleted netns $ns"
		exit 0
	fi
	if ! exists; then
		echo "interface $name does not exist" >&2
		exit 1
	fi
	ip link set dev "$name" down
	ip tuntap del dev "$name" mode tun
	echo "deleted $name"
	;;
status)
	if [[ -n $ns ]]; then
		need_root
	fi
	in_ns ip -d addr show dev "$name"
	;;
*)
	usage
	;;
esac
