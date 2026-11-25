package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	geo "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"go4.org/netipx"
	"google.golang.org/protobuf/proto"
)

const whitelist = "RU-WHITELIST"

// IANA special-purpose IPv4/IPv6 registries (2025-10-09), coalesced.
// Also exclude IPv4 multicast and IPv6 space outside 2000::/3 global unicast.
var excludedPrefixes = strings.Fields(`
	0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
	172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.31.196.0/24 192.52.193.0/24
	192.88.99.0/24 192.168.0.0/16 192.175.48.0/24 198.18.0.0/15
	198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
	::/3 4000::/2 8000::/1 2001::/23 2001:db8::/32 2002::/16
	2620:4f:8000::/48 3fff::/20
`)

var domainMatchers = map[string]struct {
	xray   geo.Domain_Type
	mihomo string
}{
	"domain":  {geo.Domain_RootDomain, "DOMAIN-SUFFIX"},
	"full":    {geo.Domain_Full, "DOMAIN"},
	"keyword": {geo.Domain_Plain, "DOMAIN-KEYWORD"},
}

var domainValue = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

func readRules(path, field string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var input struct {
		Rules []map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var values []string
	for i, rule := range input.Rules {
		var group []string
		if err := json.Unmarshal(rule[field], &group); err != nil {
			return nil, fmt.Errorf("%s: rules[%d].%s: %w", path, i, field, err)
		}
		values = append(values, group...)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s: empty %s rules", path, field)
	}
	return values, nil
}

func compileDomains(values []string) (*geo.GeoSite, []byte, error) {
	entry := &geo.GeoSite{CountryCode: whitelist}
	var text strings.Builder
	seen := make(map[string]bool)
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		kind, name, _ := strings.Cut(value, ":")
		matcher, ok := domainMatchers[kind]
		if !ok || !domainValue.MatchString(name) {
			return nil, nil, fmt.Errorf("unsupported domain rule %q", value)
		}
		entry.Domain = append(entry.Domain, &geo.Domain{Type: matcher.xray, Value: name})
		fmt.Fprintf(&text, "%s,%s\n", matcher.mihomo, name)
	}
	return entry, []byte(text.String()), nil
}

func compileIPs(values []string) (*geo.GeoIP, []byte, error) {
	var set netipx.IPSetBuilder
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, err
		}
		set.AddPrefix(prefix)
	}
	for _, prefix := range excludedPrefixes {
		set.RemovePrefix(netip.MustParsePrefix(prefix))
	}
	networks, err := set.IPSet()
	if err != nil {
		return nil, nil, err
	}
	prefixes := networks.Prefixes()
	if len(prefixes) == 0 {
		return nil, nil, fmt.Errorf("no service IP ranges remain after exclusions")
	}
	entry := &geo.GeoIP{CountryCode: whitelist}
	var text strings.Builder
	for _, prefix := range prefixes {
		entry.Cidr = append(entry.Cidr, &geo.CIDR{Ip: prefix.Addr().AsSlice(), Prefix: uint32(prefix.Bits())})
		fmt.Fprintln(&text, prefix)
	}
	return entry, []byte(text.String()), nil
}

func readGeodata(path string, message proto.Message) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(data, message); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func replaceWhitelist[Entry interface{ GetCountryCode() string }](entries []Entry, replacement Entry) []Entry {
	return append(slices.DeleteFunc(entries, func(entry Entry) bool {
		return strings.EqualFold(entry.GetCountryCode(), whitelist)
	}), replacement)
}

func build(input, output string) error {
	domainValues, err := readRules(filepath.Join(input, "domains.json"), "domain")
	if err != nil {
		return err
	}
	domainEntry, domainText, err := compileDomains(domainValues)
	if err != nil {
		return err
	}
	ipValues, err := readRules(filepath.Join(input, "IP.json"), "ip")
	if err != nil {
		return err
	}
	ipEntry, ipText, err := compileIPs(ipValues)
	if err != nil {
		return err
	}

	geosite, geoip := &geo.GeoSiteList{}, &geo.GeoIPList{}
	if err := readGeodata(filepath.Join(input, "geosite.dat"), geosite); err != nil {
		return err
	}
	if err := readGeodata(filepath.Join(input, "geoip.dat"), geoip); err != nil {
		return err
	}
	geosite.Entry = replaceWhitelist(geosite.Entry, domainEntry)
	geoip.Entry = replaceWhitelist(geoip.Entry, ipEntry)

	for name, data := range map[string]proto.Message{"geosite.dat": geosite, "geoip.dat": geoip} {
		raw, err := proto.Marshal(data)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(output, name), raw, 0644); err != nil {
			return err
		}
	}
	for name, data := range map[string][]byte{"whitelist-domains.txt": domainText, "whitelist-ips.txt": ipText} {
		if err := os.WriteFile(filepath.Join(output, name), data, 0644); err != nil {
			return err
		}
	}
	fmt.Printf("Compiled %d domain matchers and %d IP prefixes\n", len(domainEntry.Domain), len(ipEntry.Cidr))
	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage: go run . INPUT_DIRECTORY OUTPUT_DIRECTORY")
		os.Exit(2)
	}
	if err := build(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
