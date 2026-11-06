#!/bin/sh
# Copyright 2022 Helmut Grohne <helmut@subdivi.de>
# SPDX-License-Identifier: MIT
#
# This is a mmdebstrap customize hook that enables and configures
# systemd-networkd on various Debian releases.

set -eu

TARGET=$1

SYSTEMD_VERSION=$(dpkg-query --root "$TARGET" -f '${Version}' -W systemd)

if test "${MMDEBSTRAP_MODE:-}" = chrootless; then
	systemctl --root "$TARGET" enable systemd-networkd.service
else
	chroot "$TARGET" systemctl enable systemd-networkd.service
fi

if dpkg --compare-versions "$SYSTEMD_VERSION" lt 249; then
  # This anchor is included by default since bullseye. Fails DNSSEC
  # validation when missing.
  DNSOPT="DNSSECNegativeTrustAnchors=home.arpa"
else
  DNSOPT=""
fi

# Gate G1 onboard controllers. Both paths must be present before the
# ports are bridged. Edge, Patron and Unipi 1 use other paths and keep
# a DHCP client on each interface.
gate_eth0_path=platform-ff550000.ethernet
gate_eth1_path=platform-ff540000.ethernet
gate_eth0=0
gate_eth1=0
for i in $(find  "$1/lib/systemd/network" -name \*.template -printf "%P\n") ; do
    if grep -q "$gate_eth0_path" "$1/lib/systemd/network/$i"; then
        gate_eth0=1
    fi
    if grep -q "$gate_eth1_path" "$1/lib/systemd/network/$i"; then
        gate_eth1=1
    fi
done
gate_bridge=0
if [ "$gate_eth0" = 1 ] && [ "$gate_eth1" = 1 ]; then
    gate_bridge=1
fi

for i in $(find  "$1/lib/systemd/network" -name \*.template -printf "%P\n") ; do
    name=${i%.template}
    src="$1/lib/systemd/network/$i"
    if [ "$gate_bridge" = 1 ] && grep -q "$gate_eth0_path" "$src"; then
        prefix=15
    elif [ "$gate_bridge" = 1 ] && grep -q "$gate_eth1_path" "$src"; then
        prefix=16
    else
        prefix=
    fi
    if [ -n "$prefix" ]; then
        # Sort before 20-*.network and 50-fallback.network. The first
        # lexical match wins, so these ports must not keep their own DHCP.
        (
        sed '/^#/d' "$src"
        cat <<EOF
[Network]
Bridge=br0
DHCP=no
LinkLocalAddressing=no
MulticastDNS=no
LLMNR=no

[Link]
RequiredForOnline=no
EOF
        ) > "$1/etc/systemd/network/${prefix}-${name}-br.network"
    else
        (
        sed '/^#/d' "$src"
        cat <<EOF
[Network]
DHCP=yes
MulticastDNS=yes
LinkLocalAddressing=fallback
$DNSOPT

[DHCPv4]
ClientIdentifier=mac
UseHostname=no
EOF
        )  > "$1/etc/systemd/network/20-$name.network"
    fi
done

if [ "$gate_bridge" = 1 ]; then
    # MACAddress=none and the link policy leave the bridge address to the
    # kernel (lowest hardware MAC of the members). Nothing is stored, so a
    # cloned image does not copy it. STP stays off: one uplink only.
    cat > "$1/etc/systemd/network/10-br0.netdev" <<EOF
[NetDev]
Name=br0
Kind=bridge
MACAddress=none

[Bridge]
STP=no
EOF
    cat > "$1/etc/systemd/network/10-br0.link" <<EOF
[Match]
OriginalName=br0

[Link]
MACAddressPolicy=none
EOF
    cat > "$1/etc/systemd/network/11-br0.network" <<EOF
[Match]
Name=br0

[Network]
DHCP=yes
MulticastDNS=yes
LinkLocalAddressing=fallback
$DNSOPT

[DHCPv4]
ClientIdentifier=mac
UseHostname=no
EOF
fi

## Create fallback rule for virtual ethernet in qemu
cat << EOF > "$1/etc/systemd/network/50-fallback.network"
[Match]
Name=en*
Name=eth*

[Network]
DHCP=yes
$DNSOPT

[DHCP]
UseDomains=yes
EOF
