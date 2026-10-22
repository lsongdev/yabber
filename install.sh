#!/bin/sh
# Install or upgrade yabber from a GitHub release.
#
#   curl -fsSL https://github.com/lsongdev/yabber/releases/latest/download/install.sh | sh
#   sh install.sh -v 2026.10.22    install a specific release
#   sh install.sh -n               install the binary only, no service
#
# On OpenWrt it installs /usr/bin/yabber and a procd service with
# configuration and data in /etc/yabber. On systemd hosts it installs
# /usr/local/bin/yabber, a yabber user and a unit with configuration and
# data in /var/lib/yabber. Running it again upgrades the
# binary and service files; an existing configuration is never touched.
#
# YABBER_MIRROR replaces the download location with a directory holding one
# release's files. SHA256SUMS is signed by the yabber release key; the
# signature is checked when openssl supports Ed25519, and a mirror is only
# trusted when it is.

set -eu

REPO=lsongdev/yabber
VERSION=latest
SERVICE=1

say() { printf '%s\n' "$*"; }
die() {
	printf 'install.sh: %s\n' "$*" >&2
	exit 1
}

usage() {
	say "usage: install.sh [-v VERSION] [-n]"
	say "  -v VERSION  release to install (default: latest)"
	say "  -n          install the binary only"
}

while getopts v:nh opt; do
	case $opt in
	v) VERSION=$OPTARG ;;
	n) SERVICE=0 ;;
	h)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
done

if [ "$VERSION" = latest ]; then
	BASE=https://github.com/$REPO/releases/latest/download
else
	BASE=https://github.com/$REPO/releases/download/$VERSION
fi
BASE=${YABBER_MIRROR:-$BASE}

RELEASE_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZD30+ASsK/qKYEJ6xj2S7qb/sBKa/p6giw4fxjHNVfE=
-----END PUBLIC KEY-----'

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl or wget is required"
	fi || die "download failed: $1"
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# download NAME DEST fetches a release file and checks it against SHA256SUMS.
download() {
	fetch "$BASE/$1" "$2"
	want=$(awk -v name="$1" '$2 == name { print $1 }' "$TMP/SHA256SUMS")
	[ -n "$want" ] || die "SHA256SUMS has no entry for $1"
	[ "$(sha256 "$2")" = "$want" ] || die "checksum mismatch for $1"
}

# verify_signature checks SHA256SUMS against the release key. Without an
# Ed25519-capable openssl it relies on HTTPS from GitHub and refuses mirrors.
verify_signature() {
	if command -v openssl >/dev/null 2>&1 &&
		printf '%s\n' "$RELEASE_KEY" >"$TMP/release.pem" &&
		openssl pkey -pubin -in "$TMP/release.pem" -noout >/dev/null 2>&1; then
		fetch "$BASE/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig"
		if ! openssl base64 -d -A -in "$TMP/SHA256SUMS.sig" -out "$TMP/SHA256SUMS.bin" ||
			! openssl pkeyutl -verify -pubin -inkey "$TMP/release.pem" -rawin \
				-in "$TMP/SHA256SUMS" -sigfile "$TMP/SHA256SUMS.bin" >/dev/null 2>&1; then
			die "SHA256SUMS is not signed by the yabber release key"
		fi
		say "release signature verified"
	elif [ -n "${YABBER_MIRROR:-}" ]; then
		die "cannot verify the release signature (openssl with Ed25519 is needed) and will not trust a mirror without it"
	fi
}

little_endian() {
	[ "$(printf '\001\000' | od -An -tu2 | tr -d ' ')" = 1 ]
}

# asset_name prints the release binary for this machine, using OpenWrt's
# package architecture where available since it names the CPU precisely.
asset_name() {
	# busybox tr has no character classes.
	# shellcheck disable=SC2018,SC2019
	os=$(uname -s | tr 'A-Z' 'a-z')
	machine=$(uname -m)
	if [ -r /etc/openwrt_release ]; then
		# shellcheck source=/dev/null
		machine=$(. /etc/openwrt_release && echo "$DISTRIB_ARCH")
	fi
	case $machine in
	x86_64 | amd64) arch=amd64 ;;
	aarch64* | arm64) arch=arm64 ;;
	armv7* | arm_cortex-a*) arch=arm_v7 ;;
	armv6* | arm_arm1176*) arch=arm_v6 ;;
	mipsel* | mipsle*) arch=mipsle_softfloat ;;
	mips64*) die "mips64 is not supported" ;;
	mips*)
		if little_endian; then arch=mipsle_softfloat; else arch=mips_softfloat; fi
		;;
	riscv64) arch=riscv64 ;;
	*) die "unsupported architecture: $machine" ;;
	esac
	echo "yabber_${os}_${arch}"
}

[ "$(id -u)" = 0 ] || die "run as root"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

if [ -r /etc/openwrt_release ]; then
	PLATFORM=openwrt
	BIN=/usr/bin/yabber
	CONFIG=/etc/yabber/config.yaml
elif [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then
	PLATFORM=systemd
	BIN=/usr/local/bin/yabber
	CONFIG=/var/lib/yabber/config.yaml
else
	PLATFORM=other
	BIN=/usr/local/bin/yabber
	SERVICE=0
fi

ASSET=$(asset_name)
say "installing $ASSET ($VERSION) for $PLATFORM"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"
verify_signature
download "$ASSET" "$TMP/yabber"
chmod 755 "$TMP/yabber"
"$TMP/yabber" version >/dev/null 2>&1 || die "the downloaded binary does not run on this machine"

mkdir -p "$(dirname "$BIN")"
cp "$TMP/yabber" "$BIN.new"
mv -f "$BIN.new" "$BIN"
say "installed $("$BIN" version)"

[ "$SERVICE" = 1 ] || exit 0

FRESH=0
if [ ! -e "$CONFIG" ]; then
	FRESH=1
	mkdir -p "$(dirname "$CONFIG")"
	cat >"$CONFIG" <<'EOF'
# yabber configuration: https://github.com/lsongdev/yabber
sites:
  - hosts: [example.com]
    respond: hello from yabber
EOF
	say "wrote a starter configuration to $CONFIG"
fi

case $PLATFORM in
openwrt)
	download yabber.init "$TMP/yabber.init"
	cp "$TMP/yabber.init" /etc/init.d/yabber
	chmod 755 /etc/init.d/yabber
	if [ ! -e /etc/config/yabber ]; then
		cat >/etc/config/yabber <<'EOF'
config yabber 'main'
	# Serve the management panel and API on this address, for example the
	# LAN address of the router: option admin '192.168.1.1:9180'
	option admin ''
EOF
	fi
	for path in /usr/bin/yabber /etc/init.d/yabber /etc/yabber/; do
		grep -qxF "$path" /etc/sysupgrade.conf 2>/dev/null || echo "$path" >>/etc/sysupgrade.conf
	done
	/etc/init.d/yabber enable
	START="/etc/init.d/yabber start"
	RESTART="/etc/init.d/yabber restart"
	if netstat -tln 2>/dev/null | grep -qE ':(80|443) ' && pidof uhttpd >/dev/null 2>&1; then
		say "note: uhttpd holds port 80/443; move LuCI elsewhere first, for example:"
		say "  uci set uhttpd.main.listen_http='127.0.0.1:88 192.168.1.1:88'"
		say "  uci delete uhttpd.main.listen_https; uci commit uhttpd; /etc/init.d/uhttpd restart"
	fi
	;;
systemd)
	download yabber.service "$TMP/yabber.service"
	if ! id yabber >/dev/null 2>&1; then
		useradd --system --no-create-home --shell /usr/sbin/nologin yabber 2>/dev/null ||
			adduser --system --no-create-home --group yabber
	fi
	chown -R yabber:yabber /var/lib/yabber
	chmod 700 /var/lib/yabber
	cp "$TMP/yabber.service" /etc/systemd/system/yabber.service
	systemctl daemon-reload
	systemctl enable yabber >/dev/null 2>&1
	START="systemctl start yabber"
	RESTART="systemctl restart yabber"
	;;
esac

if [ "$FRESH" = 1 ]; then
	say "edit $CONFIG, then start yabber with: $START"
else
	say "restarting: $RESTART"
	$RESTART || die "restart failed; check the log"
fi
