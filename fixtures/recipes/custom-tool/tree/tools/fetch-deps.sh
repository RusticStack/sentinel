#!/bin/sh
# fetch-deps.sh <manifest> <store> <out> — the recipe's dependency tool.
# Each `name version` line is fetched into <store> (a tool-managed
# download dir: a blob already there is never re-fetched) and then
# materialized under <out>/<name>/ — <out> is the manifest's exact
# materialization, so a package whose recorded version already matches
# is left alone while anything stale is rebuilt.
set -eu

manifest=$1
store=$2
out=$3
mkdir -p "$store" "$out"

while read -r name ver; do
    [ -n "$name" ] || continue
    pkg="$name-$ver.pkg"
    if [ -f "$store/$pkg" ]; then
        echo "cached $pkg"
    else
        cp "pkgs/$pkg" "$store/$pkg"
        echo "fetched $pkg"
    fi
    if [ -f "$out/$name/.version" ] && [ "$(cat "$out/$name/.version")" = "$ver" ]; then
        echo "materialized $name $ver"
        continue
    fi
    rm -rf "$out/$name"
    mkdir -p "$out/$name"
    tar -xzf "$store/$pkg" -C "$out/$name"
    echo "$ver" > "$out/$name/.version"
    echo "materialized $name $ver"
done < "$manifest"
