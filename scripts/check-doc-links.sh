#!/usr/bin/env bash
# Fail when a Markdown link points at a file or heading anchor that does not exist.
#
#   scripts/check-doc-links.sh [file.md ...]
#
# Without arguments it checks README.md, AGENTS.md, plan.md, TODO.md and docs/*.md. It checks
# relative links to files, and `#anchor` fragments against the target's headings using GitHub's
# slug rules (lower case, punctuation dropped, spaces to hyphens, -1/-2 for repeated headings).
# External links are not fetched. Links inside fenced code and inline code are ignored.
set -u
cd "$(dirname "$0")/.."

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=(README.md AGENTS.md plan.md TODO.md docs/*.md)
fi

slugs() { # the anchors of one file's headings, one per line
  awk '
    /^```/ { fence = !fence; next }
    fence { next }
    /^#+ / {
      h = $0; sub(/^#+ +/, "", h); sub(/ +#+ *$/, "", h)
      gsub(/\[([^]]*)\]\([^)]*\)/, "&", h)
      print h
    }' "$1" |
    sed -E 's/\[([^]]*)\]\([^)]*\)/\1/g; s/`//g; s/[*_]{1,2}([^*_]*)[*_]{1,2}/\1/g' |
    tr 'A-Z' 'a-z' |
    sed -E 's/[^[:alnum:] _-]//g; s/ /-/g' |
    awk '{ n = seen[$0]++; print (n ? $0 "-" n : $0) }'
}

links() { # file:line:target for every inline link outside code
  awk '
    /^```/ { fence = !fence; next }
    fence { next }
    {
      line = $0
      gsub(/`[^`]*`/, "", line)
      while (match(line, /\]\([^) ]+[^)]*\)/)) {
        t = substr(line, RSTART + 2, RLENGTH - 3)
        sub(/ .*/, "", t)
        print FILENAME ":" FNR ":" t
        line = substr(line, RSTART + RLENGTH)
      }
    }' "$1"
}

bad=0
for file in "${files[@]}"; do
  dir=$(dirname "$file")
  while IFS=: read -r src line target; do
    case "$target" in
      http://* | https://* | mailto:* | "") continue ;;
    esac
    path=${target%%#*}
    frag=""
    case "$target" in *'#'*) frag=${target#*#} ;; esac
    if [ -z "$path" ]; then dest=$src; else dest="$dir/$path"; fi
    if [ ! -e "$dest" ]; then
      echo "$src:$line: $target: no such file" >&2
      bad=1
      continue
    fi
    if [ -n "$frag" ] && [ -f "$dest" ]; then
      case "$dest" in *.md) ;; *) continue ;; esac
      if ! slugs "$dest" | grep -qx -- "$frag"; then
        echo "$src:$line: $target: no heading with that anchor" >&2
        bad=1
      fi
    fi
  done < <(links "$file")
done
exit "$bad"
