#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 OUTPUT_DIRECTORY (must not exist)" >&2
  exit 2
fi
parent=$(realpath -e -- "$(dirname -- "$1")")
output="$parent/$(basename -- "$1")"
if [[ -e "$output" || -L "$output" ]]; then
  echo "Output already exists: $output" >&2
  exit 2
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
work=$(mktemp -d "$parent/.routing-build.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/input" "$work/assets"

read -r _ _ mihomo_version _ < <(mihomo -v)
if [[ "$mihomo_version" != v1.19.27 ]]; then
  echo "Mihomo v1.19.27 is required to produce the pinned MRS format" >&2
  exit 1
fi

download() {
  local name=$1 url=$2 digest=$3
  local file="$work/input/$name"
  curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 -o "$file" "$url"
  printf '%s  %s\n' "$digest" "$file" | sha256sum --check --status
}

m3t=https://raw.githubusercontent.com/NNN706/M3T/53daa5a68ed2e1132666e2a892cb5890d1930492/source/routing/generated
base=https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/download/202611250000

download domains.json "$m3t/domains.json" 791a1bcd565eb559062102d16392376d3d08f43a19408386be83e864421e65b3
download IP.json "$m3t/IP.json" f3f01458cda79cc4f4216afdf0c276614be38edb53d778e96ce55ccd259bc6a4
download geosite.dat "$base/geosite.dat" 68c8ba4cd43694e77a7980c7eb89f2eb0a9216137de4a1575079aead0432d373
download geoip.dat "$base/geoip.dat" 782b61d00230439ffa30dca9446a1457ef78f249e4793af1cc6bdac965c438f0

go run . "$work/input" "$work/assets"
mihomo convert-ruleset ipcidr text "$work/assets/whitelist-ips.txt" "$work/assets/whitelist-ips.mrs"
mihomo convert-ruleset ipcidr mrs "$work/assets/whitelist-ips.mrs" "$work/round-trip.txt"
cmp "$work/assets/whitelist-ips.txt" "$work/round-trip.txt"
rm "$work/assets/whitelist-ips.txt"

cat >"$work/xray.json" <<'JSON'
{
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "routing": {
    "rules": [
      {"type": "field", "outboundTag": "direct", "domain": ["geosite:private", "geosite:category-ru", "geosite:ru-available-only-inside", "geosite:category-ai-cn", "geosite:ru-whitelist"]},
      {"type": "field", "outboundTag": "direct", "ip": ["geoip:private", "geoip:ru-whitelist"]}
    ]
  }
}
JSON
XRAY_LOCATION_ASSET="$work/assets" xray run -test -config "$work/xray.json"

cat >"$work/mihomo.yaml" <<'YAML'
rule-providers:
  whitelist-domains:
    type: file
    behavior: classical
    format: text
    path: ./assets/whitelist-domains.txt
  whitelist-ips:
    type: file
    behavior: ipcidr
    format: mrs
    path: ./assets/whitelist-ips.mrs
rules:
  - RULE-SET,whitelist-domains,REJECT
  - RULE-SET,whitelist-ips,REJECT,no-resolve
  - MATCH,DIRECT
YAML
(
  socket_dir=$(mktemp -d /tmp/routing-mihomo.XXXXXXXX)
  socket="$socket_dir/core.sock"
  mihomo -d "$work" -f "$work/mihomo.yaml" -ext-ctl-unix "$socket" >"$work/mihomo.log" 2>&1 &
  pid=$!
  trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf -- "$socket_dir"' EXIT
  domains=$(wc -l <"$work/assets/whitelist-domains.txt")
  ips=$(wc -l <"$work/round-trip.txt")
  for attempt in {1..20}; do
    if curl -fs --max-time 1 --unix-socket "$socket" http://localhost/providers/rules |
      jq -e --argjson domains "$domains" --argjson ips "$ips" \
        '.providers["whitelist-domains"].ruleCount == $domains and
         .providers["whitelist-ips"].ruleCount == $ips' >/dev/null; then
      echo "Mihomo loaded $domains domain rules and $ips IP prefixes"
      exit 0
    fi
    sleep 0.25
  done
  cat "$work/mihomo.log" >&2
  echo "Mihomo did not load the expected provider rule counts" >&2
  exit 1
)

for name in geoip.dat geosite.dat whitelist-domains.txt whitelist-ips.mrs; do
  file="$work/assets/$name"
  read -r digest _ < <(sha256sum -- "$file")
  printf '%s\n' "$digest" >"$file.sha256"
done
mv -nT -- "$work/assets" "$output"
if [[ -d "$work/assets" ]]; then
  echo "Output already exists: $output" >&2
  exit 1
fi
