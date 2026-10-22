#!/bin/sh
# Vendor the panel's JavaScript dependencies into static/vendor without npm.
#
# Each package is downloaded from the npm registry, checked against the
# registry's integrity hash, and the ES modules the panel uses are copied
# unmodified, with their source maps and license, under the same paths as
# in the package. static/index.html maps the bare specifiers ("preact",
# "preact/hooks", "htm") to these files with an import map.
#
# To upgrade, change a version and its integrity (dist.integrity at
# https://registry.npmjs.org/<package>/<version>) and run this script from
# the repository root: sh web/vendor.sh

set -eu

PREACT=11.0.1
PREACT_INTEGRITY=sha512-TNNwEq++jYNHy747LziCjPRVgEwnLSOIOAw/oYcjI3Tdnubx2EXtt76I0an8PATvUWtx/DX1kFIg1eFN+O/fkw==
HTM=3.1.1
HTM_INTEGRITY=sha512-983Vyg8NwUE7JkZ6NmOqpCZ+sh1bKv2iYTlUkzlWmA5JD2acKoxd4KVxbMmxX/85mtfdnDmTFoNKcg5DGAvxNQ==

OUT=web/static/vendor
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# vendor NAME VERSION INTEGRITY FILE... copies FILEs of a package verbatim.
vendor() {
	name=$1 version=$2 integrity=$3
	shift 3
	curl -fsSL -o "$TMP/$name.tgz" "https://registry.npmjs.org/$name/-/$name-$version.tgz"
	got="sha512-$(openssl dgst -sha512 -binary "$TMP/$name.tgz" | base64 | tr -d '\n')"
	if [ "$got" != "$integrity" ]; then
		echo "vendor.sh: integrity mismatch for $name@$version" >&2
		exit 1
	fi
	mkdir -p "$TMP/$name"
	tar -xzf "$TMP/$name.tgz" -C "$TMP/$name"
	rm -rf "${OUT:?}/$name"
	for file in LICENSE "$@"; do
		mkdir -p "$(dirname "$OUT/$name/$file")"
		cp "$TMP/$name/package/$file" "$OUT/$name/$file"
	done
	printf '%s@%s %s\n' "$name" "$version" "$integrity" >>"$TMP/VERSIONS"
}

vendor preact "$PREACT" "$PREACT_INTEGRITY" \
	dist/preact.mjs dist/preact.mjs.map hooks/dist/hooks.mjs hooks/dist/hooks.mjs.map
vendor htm "$HTM" "$HTM_INTEGRITY" dist/htm.mjs

rm -f "$OUT"/*.mjs "$OUT"/LICENSE.*
cp "$TMP/VERSIONS" "$OUT/VERSIONS"
echo "vendored preact $PREACT and htm $HTM into $OUT"
