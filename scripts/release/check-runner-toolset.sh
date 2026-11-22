#!/usr/bin/env bash
# The published subset (docs/runner-images.md) and the manifest the images are built from
# (examples/runner/toolset.tsv) name the same tools at the same versions, and every command an image
# refuses by name is listed there too. Fails naming each difference.
set -euo pipefail

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$root"
doc=docs/runner-images.md
failed=0

while IFS=$'	' read -r tool version os _; do
  case $tool in '' | '#'*) continue ;; esac
  grep -qF "| \`$tool\` | \`$version\` |" "$doc" || {
    echo "$doc has no row for $tool $version ($os)" >&2
    failed=1
  }
done < examples/runner/toolset.tsv

# The other direction: a row in the document that the manifest no longer carries.
while IFS= read -r line; do
  tool=$(printf '%s' "$line" | cut -d'`' -f2)
  version=$(printf '%s' "$line" | cut -d'`' -f4)
  grep -q "^$tool	$version	" examples/runner/toolset.tsv || {
    echo "$doc lists $tool $version, which examples/runner/toolset.tsv does not pin" >&2
    failed=1
  }
done < <(grep -E '^\| `[a-z]+` \| `[0-9][^`]*` \|' "$doc")

for list in examples/runner/absent.txt examples/runner/windows/absent.txt; do
  while IFS= read -r tool; do
    case $tool in '' | '#'*) continue ;; esac
    grep -qF "\`$tool\`" "$doc" || {
      echo "$doc does not name '$tool' from $list" >&2
      failed=1
    }
  done < "$list"
done

exit "$failed"
