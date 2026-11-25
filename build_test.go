package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	geo "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func writeFixture(t *testing.T, directory, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), data, 0644); err != nil {
		t.Fatal(err)
	}
}

func marshalFixture(t *testing.T, message proto.Message) []byte {
	t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readAsset(t *testing.T, directory, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBuildReplacesWhitelistAndPreservesOtherCategories(t *testing.T) {
	input, output := t.TempDir(), t.TempDir()
	writeFixture(t, input, "domains.json", []byte(`{"rules":[{"domain":["domain:example.org","full:exact.example","keyword:token","domain:example.org"]}]}`))
	writeFixture(t, input, "IP.json", []byte(`{"rules":[{"ip":["8.8.4.0/24","8.8.4.1/32","192.0.2.0/23","10.0.0.0/8","224.0.0.0/4","2001:db8::/32","2001:4860::/32","fe80::/10"]}]}`))

	site := &geo.GeoSiteList{}
	preservedSites := []string{"PRIVATE", "CATEGORY-RU", "RU-AVAILABLE-ONLY-INSIDE", "CATEGORY-AI-CN", "OTHER"}
	for _, code := range preservedSites {
		site.Entry = append(site.Entry, &geo.GeoSite{CountryCode: code, Domain: []*geo.Domain{{Value: "keep-me"}}})
	}
	site.Entry = append(site.Entry, &geo.GeoSite{CountryCode: "ru-whitelist", Domain: []*geo.Domain{{Value: "discard-me"}}})
	writeFixture(t, input, "geosite.dat", marshalFixture(t, site))
	private := &geo.GeoIP{CountryCode: "PRIVATE", Cidr: []*geo.CIDR{{Ip: []byte{10, 0, 0, 0}, Prefix: 8}}}
	ip := &geo.GeoIPList{Entry: []*geo.GeoIP{private, {CountryCode: "RU-WHITELIST", Cidr: []*geo.CIDR{{Ip: []byte{1, 1, 1, 1}, Prefix: 32}}}}}
	writeFixture(t, input, "geoip.dat", marshalFixture(t, ip))

	if err := build(input, output); err != nil {
		t.Fatal(err)
	}
	wantRules := "DOMAIN-SUFFIX,example.org\nDOMAIN,exact.example\nDOMAIN-KEYWORD,token\n"
	if got := string(readAsset(t, output, "whitelist-domains.txt")); got != wantRules {
		t.Errorf("classical rules = %q, want %q", got, wantRules)
	}
	wantCIDRs := "8.8.4.0/24\n192.0.3.0/24\n2001:4860::/32\n"
	if got := string(readAsset(t, output, "whitelist-ips.txt")); got != wantCIDRs {
		t.Errorf("CIDRs = %q, want %q", got, wantCIDRs)
	}

	gotSite := &geo.GeoSiteList{}
	if err := proto.Unmarshal(readAsset(t, output, "geosite.dat"), gotSite); err != nil {
		t.Fatal(err)
	}
	wantDomains := []*geo.Domain{
		{Type: geo.Domain_RootDomain, Value: "example.org"},
		{Type: geo.Domain_Full, Value: "exact.example"},
		{Type: geo.Domain_Plain, Value: "token"},
	}
	gotDomains := gotSite.Entry[len(preservedSites)].Domain
	if !slices.EqualFunc(gotDomains, wantDomains, func(a, b *geo.Domain) bool { return proto.Equal(a, b) }) {
		t.Errorf("GeoSite whitelist = %v, want %v", gotDomains, wantDomains)
	}
	for i, code := range preservedSites {
		if !proto.Equal(gotSite.Entry[i], site.Entry[i]) {
			t.Errorf("GeoSite %s changed", code)
		}
	}
	gotIP := &geo.GeoIPList{}
	if err := proto.Unmarshal(readAsset(t, output, "geoip.dat"), gotIP); err != nil {
		t.Fatal(err)
	}
	wantIP := &geo.GeoIP{CountryCode: "RU-WHITELIST", Cidr: []*geo.CIDR{
		{Ip: []byte{8, 8, 4, 0}, Prefix: 24},
		{Ip: []byte{192, 0, 3, 0}, Prefix: 24},
		{Ip: []byte{0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Prefix: 32},
	}}
	if want := (&geo.GeoIPList{Entry: []*geo.GeoIP{private, wantIP}}); !proto.Equal(gotIP, want) {
		t.Errorf("GeoIP = %v, want %v", gotIP, want)
	}
}
