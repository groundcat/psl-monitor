#!/usr/bin/env bash
# Manage the reg233/whois-domain-lookup git submodule used as the WHOIS fallback.
#
#   scripts/update-whois-upstream.sh            # init (if needed) + update to latest upstream main
#   scripts/update-whois-upstream.sh --init     # only check out the pinned commit (fresh clones, CI, deploy)
#   scripts/update-whois-upstream.sh --status   # show pinned vs. latest upstream commit
#   scripts/update-whois-upstream.sh --commit   # update and commit the new pin
#
# After updating, rebuild the sidecar:  docker compose up -d --build whois
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
SUB=third_party/whois-domain-lookup
BRANCH=$(git config -f .gitmodules submodule."$SUB".branch || echo main)

version() { sed -n 's/.*VERSION = "\(.*\)".*/\1/p' "$SUB/config/version.php" 2>/dev/null || true; }

case "${1:-}" in
--init)
  git submodule sync -- "$SUB"
  git submodule update --init --recursive -- "$SUB"
  echo "whois-domain-lookup at $(git -C "$SUB" rev-parse --short HEAD) ($(version))"
  exit 0
  ;;
--status)
  git submodule update --init -- "$SUB" >/dev/null
  git -C "$SUB" fetch -q origin "$BRANCH"
  pinned=$(git -C "$SUB" rev-parse --short HEAD)
  latest=$(git -C "$SUB" rev-parse --short "origin/$BRANCH")
  echo "pinned: $pinned ($(version))"
  echo "latest: $latest"
  if [ "$pinned" != "$latest" ]; then
    echo "upstream changes since pin:"
    git -C "$SUB" log --oneline "HEAD..origin/$BRANCH" | head -30
  else
    echo "up to date"
  fi
  exit 0
  ;;
"" | --commit) ;;
*)
  sed -n '2,11p' "$0"
  exit 2
  ;;
esac

before=$(git -C "$SUB" rev-parse --short HEAD 2>/dev/null || echo none)
git submodule update --init --remote --recursive -- "$SUB"
after=$(git -C "$SUB" rev-parse --short HEAD)

if [ "$before" = "$after" ]; then
  echo "whois-domain-lookup already at latest $after ($(version))"
  exit 0
fi
echo "whois-domain-lookup: $before -> $after ($(version))"
[ "$before" != none ] && git -C "$SUB" log --oneline "$before..$after" | head -30 || true

if [ "${1:-}" = "--commit" ]; then
  git add "$SUB"
  git commit -m "Update whois-domain-lookup to $after ($(version))" -- "$SUB"
else
  echo
  echo "Review, then commit the new pin:  git add $SUB && git commit -m 'Update whois-domain-lookup'"
fi
echo "Rebuild the sidecar:              docker compose up -d --build whois"
