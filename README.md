# Shared routing rules

Tagged releases provide four assets, each with a sibling `.sha256` file
containing the SHA-256 digest followed by a newline.

| Asset | Format and contents |
| --- | --- |
| `geosite.dat` | Xray GeoSite with the M3T `ru-whitelist` domain category |
| `geoip.dat` | Xray GeoIP with the M3T `ru-whitelist` IP category |
| `whitelist-domains.txt` | Mihomo classical rules for exact, suffix, and keyword matches |
| `whitelist-ips.mrs` | Mihomo IP CIDR provider |

The build uses the two generated routing exports from
[M3T main at `53daa5a`](https://github.com/NNN706/M3T/tree/53daa5a68ed2e1132666e2a892cb5890d1930492/source/routing/generated).
Both clients use the same domain matchers and IP address coverage. The CIDR
rules omit multicast, IPv6 outside global unicast, and the special-purpose
ranges recorded by IANA. Any overlapping public portion is retained.
[IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml),
[IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)

The DAT files retain the other categories from the
[RunetFreedom `202611250000` release](https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/tag/202611250000).
This build adds or replaces `ru-whitelist` in the RunetFreedom DATs as of
2026-11-25. RunetFreedom publishes its source under the
[GPL-3.0 license](https://github.com/runetfreedom/russia-v2ray-rules-dat/blob/202611250000/LICENSE).
The source for the modified bundles consists of the pinned inputs and the
build code in this repository.

## Build a release

Use Go 1.25.5 or newer, Mihomo v1.19.27, Xray, Bash, curl, jq, and GNU coreutils
on Linux. The initial build was validated with Xray v26.11.9. Run from the
commit you intend to tag and choose an output directory that does not exist.

```sh
go test ./...
./build-release.sh /tmp/shared-routing-assets
```

The script verifies the downloaded inputs against pinned SHA-256 digests.
It checks that Xray loads the required categories, that Mihomo loads both
providers with the expected rule counts, and that the MRS round-trips to the same CIDRs.
Attach all eight files to one GitHub release, then update both consumer
configurations to that tag. The DAT pair and the rule providers are intended
to move together.
