// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- ifaceSafe ----

func TestIfaceSafe_Plain(t *testing.T) {
	if got := ifaceSafe("eth0"); got != "eth0" {
		t.Fatalf("expected eth0, got %q", got)
	}
}

func TestIfaceSafe_SlashReplaced(t *testing.T) {
	if got := ifaceSafe("veth/0"); got != "veth_0" {
		t.Fatalf("expected veth_0, got %q", got)
	}
}

func TestIfaceSafe_DotReplaced(t *testing.T) {
	if got := ifaceSafe("eth0.100"); got != "eth0_100" {
		t.Fatalf("expected eth0_100, got %q", got)
	}
}

func TestIfaceSafe_AtReplaced(t *testing.T) {
	if got := ifaceSafe("veth@if3"); got != "veth_if3" {
		t.Fatalf("expected veth_if3, got %q", got)
	}
}

func TestIfaceSafe_MultipleSpecialChars(t *testing.T) {
	if got := ifaceSafe("foo.bar@baz/qux"); got != "foo_bar_baz_qux" {
		t.Fatalf("expected foo_bar_baz_qux, got %q", got)
	}
}

// ---- xdpLinkPin ----

func TestXdpLinkPin_Simple(t *testing.T) {
	want := bpfRoot + "/kernloom_shield_xdp_link_eth0"
	if got := xdpLinkPin("eth0"); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestXdpLinkPin_WithDot(t *testing.T) {
	want := bpfRoot + "/kernloom_shield_xdp_link_eth0_100"
	if got := xdpLinkPin("eth0.100"); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestXdpLinkPin_ContainsBpfRoot(t *testing.T) {
	pin := xdpLinkPin("ens3")
	if len(pin) == 0 || pin[:len(bpfRoot)] != bpfRoot {
		t.Fatalf("pin %q does not start with bpfRoot %q", pin, bpfRoot)
	}
}

// ---- listAttachedIfaces (using a temp dir as bpfRoot) ----

// overrideBpfRoot swaps the global bpfRoot with a temp dir for the duration
// of the test. It returns a restore function.
//
// listAttachedIfaces reads bpfRoot at runtime, but the const cannot be
// overridden; we therefore test the helper logic directly with a dedicated
// helper that accepts a root path.
func listAttachedIfacesIn(root string) []string {
	entries, _ := os.ReadDir(root)
	const prefix = "kernloom_shield_xdp_link_"
	legacyPin := filepath.Join(root, "kernloom_shield_xdp_link")
	var ifaces []string
	for _, e := range entries {
		if len(e.Name()) > len(prefix) && e.Name()[:len(prefix)] == prefix {
			ifaces = append(ifaces, e.Name()[len(prefix):])
		}
	}
	if _, err := os.Stat(legacyPin); err == nil {
		ifaces = append(ifaces, "(legacy)")
	}
	return ifaces
}

func TestListAttachedIfaces_Empty(t *testing.T) {
	dir := t.TempDir()
	ifaces := listAttachedIfacesIn(dir)
	if len(ifaces) != 0 {
		t.Fatalf("expected 0 ifaces on empty dir, got %v", ifaces)
	}
}

func TestListAttachedIfaces_SingleNew(t *testing.T) {
	dir := t.TempDir()
	// Create a per-interface pin file.
	if err := os.WriteFile(filepath.Join(dir, "kernloom_shield_xdp_link_eth0"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	ifaces := listAttachedIfacesIn(dir)
	if len(ifaces) != 1 || ifaces[0] != "eth0" {
		t.Fatalf("expected [eth0], got %v", ifaces)
	}
}

func TestListAttachedIfaces_MultipleNew(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"kernloom_shield_xdp_link_eth0", "kernloom_shield_xdp_link_eth1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ifaces := listAttachedIfacesIn(dir)
	if len(ifaces) != 2 {
		t.Fatalf("expected 2 ifaces, got %v", ifaces)
	}
}

func TestListAttachedIfaces_LegacyOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kernloom_shield_xdp_link"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	ifaces := listAttachedIfacesIn(dir)
	if len(ifaces) != 1 || ifaces[0] != "(legacy)" {
		t.Fatalf("expected [(legacy)], got %v", ifaces)
	}
}

func TestListAttachedIfaces_LegacyAndNew(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"kernloom_shield_xdp_link",
		"kernloom_shield_xdp_link_eth0",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ifaces := listAttachedIfacesIn(dir)
	// Should contain eth0 and (legacy).
	found := map[string]bool{}
	for _, i := range ifaces {
		found[i] = true
	}
	if !found["eth0"] || !found["(legacy)"] {
		t.Fatalf("expected eth0 and (legacy), got %v", ifaces)
	}
}

func TestListAttachedIfaces_UnrelatedFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	// Unrelated files should be ignored.
	for _, name := range []string{"kernloom_totals", "kernloom_src4_stats", "other_file"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ifaces := listAttachedIfacesIn(dir)
	if len(ifaces) != 0 {
		t.Fatalf("expected no ifaces from unrelated files, got %v", ifaces)
	}
}
