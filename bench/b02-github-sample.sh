#!/usr/bin/env bash
# B02: drive samples of the lockwell-ci contract's `unit` lane on a GitHub
# self-hosted runner. Each sample is one push to the bench branch of a
# Lockwell worktree (an empty commit, or the condition file changing), and
# waits for the run it triggered.
#   bench/b02-github-sample.sh WORKTREE CONDITION COUNT
# Afterwards bench/b02-github-collect.py turns the branch's runs into records.
set -euo pipefail
WT=$1
CONDITION=$2
COUNT=$3
REPO=RusticStack/lockwell
BRANCH=sentinel-bench/b02
cd "$WT"
for n in $(seq 1 "$COUNT"); do
  if [ "$(cat .sentinel-bench-condition 2>/dev/null)" != "$CONDITION" ]; then
    echo "$CONDITION" > .sentinel-bench-condition
    git add .sentinel-bench-condition
    git commit -q -m "bench: condition $CONDITION"
  else
    git commit -q --allow-empty -m "bench: $CONDITION sample"
  fi
  sha=$(git rev-parse HEAD)
  git push -q origin "$BRANCH"
  id=""
  for _ in $(seq 1 60); do
    id=$(gh run list -R "$REPO" --branch "$BRANCH" --limit 5 --json databaseId,headSha \
      --jq ".[] | select(.headSha == \"$sha\") | .databaseId" | head -1)
    [ -n "$id" ] && break
    sleep 2
  done
  [ -n "$id" ] || { echo "no run appeared for $sha" >&2; exit 1; }
  gh run watch -R "$REPO" "$id" --exit-status --interval 5 >/dev/null
  echo "$CONDITION $n run $id sha $sha: ok"
done
