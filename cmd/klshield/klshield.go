// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	// bpfRoot is the BPF filesystem mount point.
	bpfRoot = "/sys/fs/bpf"

	// pinXdpLinkLegacy is kept for detecting and cleaning up old single-interface
	// installations. New code uses xdpLinkPin(iface) which is per-interface.
	pinXdpLinkLegacy = "/sys/fs/bpf/kernloom_shield_xdp_link"

	// pinned maps (per Kernloom docs)
	pinTotals     = "/sys/fs/bpf/kernloom_totals"
	pinSrc4Stats  = "/sys/fs/bpf/kernloom_src4_stats"
	pinSrc6Stats  = "/sys/fs/bpf/kernloom_src6_stats"
	pinFlow4Stats = "/sys/fs/bpf/kernloom_flow4_stats"

	pinAllow4LPM = "/sys/fs/bpf/kernloom_allow4_lpm"
	pinDeny4Hash = "/sys/fs/bpf/kernloom_deny4_hash"
	pinAllow6LPM = "/sys/fs/bpf/kernloom_allow6_lpm"
	pinDeny6Hash = "/sys/fs/bpf/kernloom_deny6_hash"

	pinCfg = "/sys/fs/bpf/kernloom_cfg"

	pinRLCfg     = "/sys/fs/bpf/kernloom_rl_cfg"
	pinRLPolicy4 = "/sys/fs/bpf/kernloom_rl_policy4"
	pinRLPolicy6 = "/sys/fs/bpf/kernloom_rl_policy6"

	// Tuple (edge) enforcement maps.
	pinEdge4Deny  = "/sys/fs/bpf/kernloom_edge4_deny"
	pinEdge4Allow = "/sys/fs/bpf/kernloom_edge4_allow"
	pinEdge4RL    = "/sys/fs/bpf/kernloom_edge4_rl_policy"
	pinEdge4Cfg   = "/sys/fs/bpf/kernloom_edge4_cfg"

	pinEvents = "/sys/fs/bpf/kernloom_events"
)

/* ---------------- Types ---------------- */

type xdpCfg struct {
	EnforceAllow    uint32
	EventSampleMask uint32
}

type rlCfg struct {
	RatePPS uint64
	Burst   uint64
}

type lpmKey4 struct {
	Prefixlen uint32
	Data      [4]byte
}
type lpmKey6 struct {
	Prefixlen uint32
	Data      [16]byte
}

type key4Bytes struct{ IP [4]byte }
type key6Bytes struct{ IP [16]byte }
type src6Key struct{ IP [16]byte }

// edge4Key matches struct edge4_key in xdp_kernloom_shield.bpf.c.
// All fields must be in the exact same order and size as the BPF struct.
type edge4Key struct {
	SrcIP   [4]byte
	DstPort uint16 // host byte order
	Proto   uint8
	Pad     uint8 // must be zero
}

type edge4CfgValue struct {
	Enforce uint32 // 0=off, 1=deny-mode, 2=allow-mode
	Pad     uint32
}

// MUST match Shield C layout for xdp_src_stats_v4_t (including explicit padding).
type src4Stats struct {
	Pkts  uint64
	Bytes uint64

	TCP  uint64
	UDP  uint64
	ICMP uint64

	SYN    uint64
	SYNACK uint64
	RST    uint64
	ACK    uint64

	Pass      uint64
	DropAllow uint64
	DropDeny  uint64
	DropRL    uint64

	FirstSeenNs uint64
	LastSeenNs  uint64

	LastSport uint16
	LastDport uint16
	Pad0      [4]byte

	DportChanges uint64

	LastTTL      uint8
	LastTCPFlags uint8
	Pad1         [2]byte
	Pad2         [4]byte
}

// Totals: MUST match Shield C layout for xdp_totals_t.
type xdpTotals struct {
	Pkts       uint64
	Bytes      uint64
	Pass       uint64
	DropAllow  uint64
	DropDeny   uint64
	DropRL     uint64
	V4         uint64
	V6         uint64
	TCP        uint64
	UDP        uint64
	ICMP       uint64
	SYN        uint64
	SYNACK     uint64
	RST        uint64
	ACK        uint64
	IPv4Frags  uint64
	DportChg   uint64
	NewSources uint64
	AllowHits  uint64
	DenyHits   uint64
	RLHits     uint64
}

type xdpEvent struct {
	TsNs    uint64
	Reason  uint32
	IPVer   uint8
	L4Proto uint8
	Dport   uint16
	SaddrV4 [4]byte
	SaddrV6 [16]byte
	PktLen  uint32
	Aux     uint32
}

type bpfObjects struct {
	// Program: support both symbol names during transition:
	// - new: xdp_klshield
	// - old: xdp_netguard
	XdpProgram *ebpf.Program

	XdpTotals     *ebpf.Map
	XdpSrc4Stats  *ebpf.Map
	XdpSrc6Stats  *ebpf.Map
	XdpFlow4Stats *ebpf.Map

	XdpAllowLpm  *ebpf.Map
	XdpDenyHash4 *ebpf.Map
	XdpAllow6Lpm *ebpf.Map
	XdpDenyHash6 *ebpf.Map
	XdpCfg       *ebpf.Map

	XdpRLCfg     *ebpf.Map
	XdpRLPolicy4 *ebpf.Map
	XdpRLPolicy6 *ebpf.Map

	// Tuple enforcement maps (may be nil on older Shield builds).
	XdpEdge4Deny  *ebpf.Map
	XdpEdge4Allow *ebpf.Map
	XdpEdge4RL    *ebpf.Map
	XdpEdge4Cfg   *ebpf.Map

	XdpEventsRing *ebpf.Map

	coll *ebpf.Collection
}

func (o *bpfObjects) Close() {
	if o != nil && o.coll != nil {
		o.coll.Close()
		o.coll = nil
	}
}

/* ---------------- Helpers ---------------- */

func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
func mustIf(cond bool, msg string) {
	if cond {
		must(errors.New("invalid"), msg)
	}
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func openPinnedMap(path string) (*ebpf.Map, error) { return ebpf.LoadPinnedMap(path, nil) }

func tryOpenPinnedMap(path string) (*ebpf.Map, bool) {
	m, err := openPinnedMap(path)
	if err != nil {
		return nil, false
	}
	return m, true
}

func pinIfMissing(m *ebpf.Map, path string) error {
	if exists(path) {
		return nil
	}
	return m.Pin(path)
}

/*
BPF uses bpf_ktime_get_ns() for timestamps => monotonic since boot.

To print wall-clock:
- approximate boot time via /proc/uptime
- wall = boot + monotonic_ns
*/
func approxBootTime() time.Time {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Now()
	}
	var upSec float64
	_, _ = fmt.Sscanf(string(b), "%f", &upSec)
	return time.Now().Add(-time.Duration(upSec * float64(time.Second)))
}

func initCfgDefaults() {
	m, err := openPinnedMap(pinCfg)
	if err != nil {
		return
	}
	defer m.Close()

	var k uint32 = 0
	var cur xdpCfg
	_ = m.Lookup(&k, &cur)

	// Reasonable default: 1/1024 sampling (mask=1023). User can set to 1 or 3 for more.
	if cur.EventSampleMask == 0 {
		cur.EventSampleMask = 1023
		_ = m.Update(&k, &cur, ebpf.UpdateAny)
	}
}

func loadBPFWithReplacements(objPath string) (*bpfObjects, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, err
	}

	// Reuse pinned maps if they exist.
	repl := map[string]*ebpf.Map{}
	for name, pin := range map[string]string{
		"xdp_totals":      pinTotals,
		"xdp_src4_stats":  pinSrc4Stats,
		"xdp_src6_stats":  pinSrc6Stats,
		"xdp_flow4_stats": pinFlow4Stats,

		"xdp_allow_lpm":  pinAllow4LPM,
		"xdp_deny_hash":  pinDeny4Hash,
		"xdp_allow6_lpm": pinAllow6LPM,
		"xdp_deny6_hash": pinDeny6Hash,

		"xdp_cfg": pinCfg,

		"xdp_rl_cfg":     pinRLCfg,
		"xdp_rl_policy4": pinRLPolicy4,
		"xdp_rl_policy6": pinRLPolicy6,

		// Tuple enforcement maps (present in new Shield builds).
		"edge4_deny":      pinEdge4Deny,
		"edge4_allow":     pinEdge4Allow,
		"edge4_rl_policy": pinEdge4RL,
		"edge4_cfg":       pinEdge4Cfg,

		"xdp_events": pinEvents,
	} {
		if m, ok := tryOpenPinnedMap(pin); ok {
			repl[name] = m
		}
	}

	opts := ebpf.CollectionOptions{MapReplacements: repl}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, err
	}

	getMap := func(name string) (*ebpf.Map, error) {
		m := coll.Maps[name]
		if m == nil {
			return nil, fmt.Errorf("missing map in object: %s", name)
		}
		return m, nil
	}

	// Program name: prefer new, fallback to old.
	var prog *ebpf.Program
	if p := coll.Programs["xdp_klshield"]; p != nil {
		prog = p
	} else if p := coll.Programs["xdp_netguard"]; p != nil {
		prog = p
	} else {
		coll.Close()
		return nil, fmt.Errorf("missing xdp program: expected xdp_klshield (new) or xdp_netguard (old)")
	}

	objs := &bpfObjects{XdpProgram: prog, coll: coll}
	var err2 error

	if objs.XdpTotals, err2 = getMap("xdp_totals"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpSrc4Stats, err2 = getMap("xdp_src4_stats"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpSrc6Stats, err2 = getMap("xdp_src6_stats"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpFlow4Stats, err2 = getMap("xdp_flow4_stats"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpAllowLpm, err2 = getMap("xdp_allow_lpm"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpDenyHash4, err2 = getMap("xdp_deny_hash"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpAllow6Lpm, err2 = getMap("xdp_allow6_lpm"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpDenyHash6, err2 = getMap("xdp_deny6_hash"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpCfg, err2 = getMap("xdp_cfg"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpRLCfg, err2 = getMap("xdp_rl_cfg"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpRLPolicy4, err2 = getMap("xdp_rl_policy4"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpRLPolicy6, err2 = getMap("xdp_rl_policy6"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpEventsRing, err2 = getMap("xdp_events"); err2 != nil {
		objs.Close()
		return nil, err2
	}

	// Tuple enforcement maps — optional; present only in new Shield builds.
	// Absence is not an error; KLIQ and klshield degrade gracefully.
	if m := coll.Maps["edge4_deny"]; m != nil {
		objs.XdpEdge4Deny = m
	}
	if m := coll.Maps["edge4_allow"]; m != nil {
		objs.XdpEdge4Allow = m
	}
	if m := coll.Maps["edge4_rl_policy"]; m != nil {
		objs.XdpEdge4RL = m
	}
	if m := coll.Maps["edge4_cfg"]; m != nil {
		objs.XdpEdge4Cfg = m
	}

	// Pin maps (names per docs) if missing.
	if err := pinIfMissing(objs.XdpTotals, pinTotals); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpSrc4Stats, pinSrc4Stats); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpFlow4Stats, pinFlow4Stats); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpSrc6Stats, pinSrc6Stats); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpAllowLpm, pinAllow4LPM); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpDenyHash4, pinDeny4Hash); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpAllow6Lpm, pinAllow6LPM); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpDenyHash6, pinDeny6Hash); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpCfg, pinCfg); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpRLCfg, pinRLCfg); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpRLPolicy4, pinRLPolicy4); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpRLPolicy6, pinRLPolicy6); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpEventsRing, pinEvents); err != nil {
		objs.Close()
		return nil, err
	}

	// Pin edge maps if present.
	if objs.XdpEdge4Deny != nil {
		_ = pinIfMissing(objs.XdpEdge4Deny, pinEdge4Deny)
	}
	if objs.XdpEdge4Allow != nil {
		_ = pinIfMissing(objs.XdpEdge4Allow, pinEdge4Allow)
	}
	if objs.XdpEdge4RL != nil {
		_ = pinIfMissing(objs.XdpEdge4RL, pinEdge4RL)
	}
	if objs.XdpEdge4Cfg != nil {
		_ = pinIfMissing(objs.XdpEdge4Cfg, pinEdge4Cfg)
	}

	initCfgDefaults()
	return objs, nil
}

func ifaceIndex(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

/* ---------------- XDP multi-interface link pins ---------------- */

// ifaceSafe converts a network interface name to a string safe for use in
// a BPF filesystem pin path (replaces '/', '.' and '@' with '_').
func ifaceSafe(iface string) string {
	return strings.NewReplacer("/", "_", ".", "_", "@", "_").Replace(iface)
}

// xdpLinkPin returns the per-interface BPF link pin path.
// Each interface gets its own pin so multiple interfaces can be attached
// simultaneously while sharing the same map set (Variante A / node-scope).
func xdpLinkPin(iface string) string {
	return bpfRoot + "/kernloom_shield_xdp_link_" + ifaceSafe(iface)
}

// listAttachedIfaces scans bpfRoot for active per-interface XDP link pins
// and returns the interface names. Also detects the legacy single-interface
// pin (kernloom_shield_xdp_link without suffix) from older installations.
func listAttachedIfaces() []string {
	entries, _ := os.ReadDir(bpfRoot)
	const prefix = "kernloom_shield_xdp_link_"
	var ifaces []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			ifaces = append(ifaces, strings.TrimPrefix(e.Name(), prefix))
		}
	}
	// Legacy single-interface installation (pre-multi-interface).
	if exists(pinXdpLinkLegacy) {
		ifaces = append(ifaces, "(legacy)")
	}
	return ifaces
}

/* ---------------- XDP Attach/Detach ---------------- */

func attachXDP(iface, obj string, force bool) {
	linkPin := xdpLinkPin(iface)

	if force {
		_ = execCommand("ip", "link", "set", "dev", iface, "xdp", "off")
		_ = os.Remove(linkPin)
	}

	objs, err := loadBPFWithReplacements(obj)
	must(err, "load BPF")
	defer objs.Close()

	if exists(linkPin) {
		fmt.Printf("XDP already attached to %s (link at %s — detach first or use --force)\n", iface, linkPin)
		return
	}

	idx, err := ifaceIndex(iface)
	must(err, "get iface index")

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgram,
		Interface: idx,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		lnk, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpProgram,
			Interface: idx,
			Flags:     link.XDPGenericMode,
		})
		must(err, "attach xdp (driver+generic failed)")
	}

	must(lnk.Pin(linkPin), "pin xdp link")
	fmt.Printf("Attached XDP to %s (link pinned at %s)\n", iface, linkPin)
}

// detachXDP detaches the XDP program from a specific interface.
// When iface is empty it auto-detects: if exactly one interface is attached
// it detaches that one; if multiple are attached it prints an error.
// The legacy single-interface pin is handled as a special case.
func detachXDP(iface string) {
	if iface == "" {
		// Try legacy pin first (old single-interface installations).
		if exists(pinXdpLinkLegacy) {
			lnk, err := link.LoadPinnedLink(pinXdpLinkLegacy, nil)
			if err == nil {
				_ = os.Remove(pinXdpLinkLegacy)
				_ = lnk.Close()
				fmt.Println("Detached XDP (legacy link removed).")
				return
			}
		}
		// Auto-detect from per-interface pins.
		attached := listAttachedIfaces()
		// Filter out legacy marker.
		var real []string
		for _, a := range attached {
			if a != "(legacy)" {
				real = append(real, a)
			}
		}
		switch len(real) {
		case 0:
			fmt.Println("No attached XDP interface found.")
			return
		case 1:
			iface = real[0]
		default:
			fmt.Fprintf(os.Stderr, "Multiple interfaces attached: %v\nUse: klshield detach-xdp --iface <iface>\n", real)
			os.Exit(1)
		}
	}

	linkPin := xdpLinkPin(iface)
	lnk, err := link.LoadPinnedLink(linkPin, nil)
	if err != nil {
		fmt.Printf("No XDP link found for interface %s (expected at %s)\n", iface, linkPin)
		return
	}
	_ = os.Remove(linkPin)
	_ = lnk.Close()
	fmt.Printf("Detached XDP from %s.\n", iface)
}

/* ---------------- Allow/Deny management ---------------- */

func addAllowCIDR(cidr string) {
	_, ipnet, err := net.ParseCIDR(cidr)
	must(err, "parse cidr")
	ones, _ := ipnet.Mask.Size()

	ip := ipnet.IP
	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinAllow4LPM)
		must(err, "open allow4 lpm")
		defer m.Close()

		var k lpmKey4
		k.Prefixlen = uint32(ones)
		copy(k.Data[:], ip4[:])
		var v uint8 = 1
		must(m.Update(&k, &v, ebpf.UpdateAny), "update allow4")
		fmt.Printf("allow4 add: %s\n", cidr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "cidr ip")
	m, err := openPinnedMap(pinAllow6LPM)
	must(err, "open allow6 lpm")
	defer m.Close()

	var k lpmKey6
	k.Prefixlen = uint32(ones)
	copy(k.Data[:], ip16[:])
	var v uint8 = 1
	must(m.Update(&k, &v, ebpf.UpdateAny), "update allow6")
	fmt.Printf("allow6 add: %s\n", cidr)
}

func listAllow() {
	// v4
	if m, err := openPinnedMap(pinAllow4LPM); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k lpmKey4
		var v uint8
		fmt.Println("Allow v4:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IPv4(k.Data[0], k.Data[1], k.Data[2], k.Data[3])
			fmt.Printf("  %s/%d\n", ip.String(), k.Prefixlen)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate allow v4 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("Allow v4: cannot open %s: %v\n", pinAllow4LPM, err)
	}

	// v6
	if m, err := openPinnedMap(pinAllow6LPM); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k lpmKey6
		var v uint8
		fmt.Println("Allow v6:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IP(k.Data[:])
			fmt.Printf("  %s/%d\n", ip.String(), k.Prefixlen)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate allow v6 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("Allow v6: cannot open %s: %v\n", pinAllow6LPM, err)
	}
}

func addDenyIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinDeny4Hash)
		must(err, "open deny4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		var v uint8 = 1
		must(m.Update(&k, &v, ebpf.UpdateAny), "update deny4")
		fmt.Printf("deny4 add: %s\n", ipStr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinDeny6Hash)
	must(err, "open deny6")
	defer m.Close()
	var k key6Bytes
	copy(k.IP[:], ip16[:])
	var v uint8 = 1
	must(m.Update(&k, &v, ebpf.UpdateAny), "update deny6")
	fmt.Printf("deny6 add: %s\n", ipStr)
}

func delDenyIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinDeny4Hash)
		must(err, "open deny4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		must(m.Delete(&k), "delete deny4")
		fmt.Printf("deny4 removed: %s\n", ipStr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinDeny6Hash)
	must(err, "open deny6")
	defer m.Close()
	var k key6Bytes
	copy(k.IP[:], ip16[:])
	must(m.Delete(&k), "delete deny6")
	fmt.Printf("deny6 removed: %s\n", ipStr)
}

func resetMaps() {
	total := 0

	// deny4
	if m, err := openPinnedMap(pinDeny4Hash); err == nil {
		defer m.Close()
		var keys []key4Bytes
		it := m.Iterate()
		var k key4Bytes
		var v uint8
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, k := range keys {
			k := k
			_ = m.Delete(&k)
			total++
		}
		fmt.Printf("deny4: cleared %d entries\n", len(keys))
	}

	// deny6
	if m, err := openPinnedMap(pinDeny6Hash); err == nil {
		defer m.Close()
		var keys []key6Bytes
		it := m.Iterate()
		var k key6Bytes
		var v uint8
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, k := range keys {
			k := k
			_ = m.Delete(&k)
			total++
		}
		fmt.Printf("deny6: cleared %d entries\n", len(keys))
	}

	// rl4
	if m, err := openPinnedMap(pinRLPolicy4); err == nil {
		defer m.Close()
		var keys []key4Bytes
		it := m.Iterate()
		var k key4Bytes
		var v rlCfg
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, k := range keys {
			k := k
			_ = m.Delete(&k)
			total++
		}
		fmt.Printf("rl4: cleared %d entries\n", len(keys))
	}

	// rl6
	if m, err := openPinnedMap(pinRLPolicy6); err == nil {
		defer m.Close()
		var keys []src6Key
		it := m.Iterate()
		var k src6Key
		var v rlCfg
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, k := range keys {
			k := k
			_ = m.Delete(&k)
			total++
		}
		fmt.Printf("rl6: cleared %d entries\n", len(keys))
	}

	fmt.Printf("reset: %d entries cleared\n", total)
}

func listDeny() {
	// v4
	if m, err := openPinnedMap(pinDeny4Hash); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k key4Bytes
		var v uint8
		fmt.Println("Deny v4:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IPv4(k.IP[0], k.IP[1], k.IP[2], k.IP[3])
			fmt.Printf("  %s\n", ip.String())
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate deny v4 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("Deny v4: cannot open %s: %v\n", pinDeny4Hash, err)
	}

	// v6
	if m, err := openPinnedMap(pinDeny6Hash); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k key6Bytes
		var v uint8
		fmt.Println("Deny v6:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IP(k.IP[:])
			fmt.Printf("  %s\n", ip.String())
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate deny v6 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	}
}

/* ---------------- Runtime cfg ---------------- */

func enforceAllow(on bool) {
	m, err := openPinnedMap(pinCfg)
	must(err, "open kernloom_cfg")
	defer m.Close()

	var k uint32 = 0
	var cur xdpCfg
	_ = m.Lookup(&k, &cur)
	if on {
		cur.EnforceAllow = 1
	} else {
		cur.EnforceAllow = 0
	}
	if cur.EventSampleMask == 0 {
		cur.EventSampleMask = 1023
	}
	must(m.Update(&k, &cur, ebpf.UpdateAny), "update cfg")
	fmt.Printf("enforce_allow=%v, event_sample_mask=%d\n", on, cur.EventSampleMask)
}

func setEventSampling(mask uint32) {
	m, err := openPinnedMap(pinCfg)
	must(err, "open kernloom_cfg")
	defer m.Close()

	var k uint32 = 0
	var cur xdpCfg
	_ = m.Lookup(&k, &cur)
	cur.EventSampleMask = mask
	must(m.Update(&k, &cur, ebpf.UpdateAny), "update cfg sampling")
	fmt.Printf("event_sample_mask=%d (0 disables events)\n", mask)
}

/* ---------------- Rate limiting ---------------- */

func rlSet(rate, burst uint64) {
	m, err := openPinnedMap(pinRLCfg)
	must(err, "open kernloom_rl_cfg")
	defer m.Close()

	var k uint32 = 0
	val := rlCfg{RatePPS: rate, Burst: burst}
	must(m.Update(&k, &val, ebpf.UpdateAny), "update rl cfg")
	fmt.Printf("rl cfg: rate=%d pps, burst=%d\n", rate, burst)
}

func rlSetIP(ipStr string, rate, burst uint64) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	val := rlCfg{RatePPS: rate, Burst: burst}

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinRLPolicy4)
		must(err, "open rl policy4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		must(m.Update(&k, &val, ebpf.UpdateAny), "update rl policy4")
		fmt.Printf("rl ip v4: %s rate=%d burst=%d\n", ipStr, rate, burst)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinRLPolicy6)
	must(err, "open rl policy6")
	defer m.Close()
	var k src6Key
	copy(k.IP[:], ip16[:])
	must(m.Update(&k, &val, ebpf.UpdateAny), "update rl policy6")
	fmt.Printf("rl ip v6: %s rate=%d burst=%d\n", ipStr, rate, burst)
}

func rlUnsetIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinRLPolicy4)
		must(err, "open rl policy4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		must(m.Delete(&k), "delete rl policy4")
		fmt.Printf("rl ip v4 removed: %s\n", ipStr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinRLPolicy6)
	must(err, "open rl policy6")
	defer m.Close()
	var k src6Key
	copy(k.IP[:], ip16[:])
	must(m.Delete(&k), "delete rl policy6")
	fmt.Printf("rl ip v6 removed: %s\n", ipStr)
}

func listRL() {
	// global cfg
	if m, err := openPinnedMap(pinRLCfg); err == nil {
		defer m.Close()
		var k uint32 = 0
		var v rlCfg
		if err := m.Lookup(&k, &v); err == nil {
			fmt.Printf("RL global: rate=%d pps burst=%d\n", v.RatePPS, v.Burst)
		} else {
			fmt.Printf("RL global: lookup err: %v\n", err)
		}
	} else {
		fmt.Printf("RL global: cannot open %s: %v\n", pinRLCfg, err)
	}

	// v4 overrides
	if m, err := openPinnedMap(pinRLPolicy4); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k key4Bytes
		var v rlCfg
		fmt.Println("RL overrides v4:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IPv4(k.IP[0], k.IP[1], k.IP[2], k.IP[3])
			fmt.Printf("  %s rate=%d burst=%d\n", ip.String(), v.RatePPS, v.Burst)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate rl v4 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("RL overrides v4: cannot open %s: %v\n", pinRLPolicy4, err)
	}

	// v6 overrides
	if m, err := openPinnedMap(pinRLPolicy6); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k src6Key
		var v rlCfg
		fmt.Println("RL overrides v6:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IP(k.IP[:])
			fmt.Printf("  %s rate=%d burst=%d\n", ip.String(), v.RatePPS, v.Burst)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate rl v6 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("RL overrides v6: cannot open %s: %v\n", pinRLPolicy6, err)
	}
}

/* ---------------- Tuple (edge) enforcement ---------------- */

func parseEdge4Key(srcStr, portStr, protoStr string) edge4Key {
	ip := net.ParseIP(srcStr)
	mustIf(ip == nil, "parse src IP")
	ip4 := ip.To4()
	mustIf(ip4 == nil, "src must be IPv4")

	var port uint64
	_, err := fmt.Sscanf(portStr, "%d", &port)
	must(err, "parse port")

	var proto uint8
	switch strings.ToLower(protoStr) {
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	case "icmp":
		proto = 1
	default:
		must(fmt.Errorf("unknown proto %q (use tcp/udp/icmp)", protoStr), "parse proto")
	}

	var k edge4Key
	copy(k.SrcIP[:], ip4)
	k.DstPort = uint16(port)
	k.Proto = proto
	return k
}

func addEdgeDeny(srcStr, portStr, protoStr string) {
	k := parseEdge4Key(srcStr, portStr, protoStr)
	m, err := openPinnedMap(pinEdge4Deny)
	must(err, "open edge4_deny (run 'klshield attach-xdp' with new .bpf.o first)")
	defer m.Close()
	v := uint8(1)
	must(m.Update(&k, &v, ebpf.UpdateAny), "update edge4_deny")
	fmt.Printf("edge deny added: src=%s port=%s proto=%s\n", srcStr, portStr, protoStr)
}

func delEdgeDeny(srcStr, portStr, protoStr string) {
	k := parseEdge4Key(srcStr, portStr, protoStr)
	m, err := openPinnedMap(pinEdge4Deny)
	must(err, "open edge4_deny")
	defer m.Close()
	if err := m.Delete(&k); err != nil {
		fmt.Printf("edge deny not found (already removed?): %v\n", err)
		return
	}
	fmt.Printf("edge deny removed: src=%s port=%s proto=%s\n", srcStr, portStr, protoStr)
}

func listEdgeDeny() {
	m, err := openPinnedMap(pinEdge4Deny)
	must(err, "open edge4_deny")
	defer m.Close()

	it := m.Iterate()
	var k edge4Key
	var v uint8
	fmt.Println("Edge deny entries:")
	n := 0
	for it.Next(&k, &v) {
		src := net.IPv4(k.SrcIP[0], k.SrcIP[1], k.SrcIP[2], k.SrcIP[3])
		proto := map[uint8]string{6: "tcp", 17: "udp", 1: "icmp"}[k.Proto]
		fmt.Printf("  src=%-15s port=%-5d proto=%s\n", src, k.DstPort, proto)
		n++
	}
	if err := it.Err(); err != nil {
		fmt.Printf("iterate edge4_deny: %v\n", err)
	}
	if n == 0 {
		fmt.Println("  (none)")
	}
}

func addEdgeAllow(srcStr, portStr, protoStr string) {
	k := parseEdge4Key(srcStr, portStr, protoStr)
	m, err := openPinnedMap(pinEdge4Allow)
	must(err, "open edge4_allow (run 'klshield attach-xdp' with new .bpf.o first)")
	defer m.Close()
	v := uint8(1)
	must(m.Update(&k, &v, ebpf.UpdateAny), "update edge4_allow")
	fmt.Printf("edge allow added: src=%s port=%s proto=%s\n", srcStr, portStr, protoStr)
}

func delEdgeAllow(srcStr, portStr, protoStr string) {
	k := parseEdge4Key(srcStr, portStr, protoStr)
	m, err := openPinnedMap(pinEdge4Allow)
	must(err, "open edge4_allow")
	defer m.Close()
	if err := m.Delete(&k); err != nil {
		fmt.Printf("edge allow not found: %v\n", err)
		return
	}
	fmt.Printf("edge allow removed: src=%s port=%s proto=%s\n", srcStr, portStr, protoStr)
}

func listEdgeAllow() {
	m, err := openPinnedMap(pinEdge4Allow)
	must(err, "open edge4_allow")
	defer m.Close()

	it := m.Iterate()
	var k edge4Key
	var v uint8
	fmt.Println("Edge allow entries (whitelist for allow-mode):")
	n := 0
	for it.Next(&k, &v) {
		src := net.IPv4(k.SrcIP[0], k.SrcIP[1], k.SrcIP[2], k.SrcIP[3])
		proto := map[uint8]string{6: "tcp", 17: "udp", 1: "icmp"}[k.Proto]
		fmt.Printf("  src=%-15s port=%-5d proto=%s\n", src, k.DstPort, proto)
		n++
	}
	if err := it.Err(); err != nil {
		fmt.Printf("iterate edge4_allow: %v\n", err)
	}
	if n == 0 {
		fmt.Println("  (none) — populate before activating 'tuple-enforce allow'")
	}
}

func setEdgeRL(srcStr, portStr, protoStr string, rate, burst uint64) {
	k := parseEdge4Key(srcStr, portStr, protoStr)
	m, err := openPinnedMap(pinEdge4RL)
	must(err, "open edge4_rl_policy")
	defer m.Close()
	v := rlCfg{RatePPS: rate, Burst: burst}
	must(m.Update(&k, &v, ebpf.UpdateAny), "update edge4_rl_policy")
	fmt.Printf("edge rl set: src=%s port=%s proto=%s rate=%d burst=%d\n",
		srcStr, portStr, protoStr, rate, burst)
}

// tupleEnforceMode sets the XDP tuple enforcement mode:
//
//	"off"   → mode 0 (disabled)
//	"on"    → mode 1 (deny-mode / blacklist): denied tuples dropped; first violation passes
//	"allow" → mode 2 (allow-mode / default-deny): only allowlisted tuples pass; no race window
func tupleEnforceMode(mode string) {
	m, err := openPinnedMap(pinEdge4Cfg)
	must(err, "open edge4_cfg (run 'klshield attach-xdp' with new .bpf.o first)")
	defer m.Close()
	var k uint32 = 0
	v := edge4CfgValue{}
	switch strings.ToLower(mode) {
	case "on", "deny":
		v.Enforce = 1
		fmt.Println("Tuple enforcement: DENY mode — edge4_deny active (blacklist).")
		fmt.Println("  First violation packet passes; KLIQ blocks subsequent ones.")
	case "allow":
		v.Enforce = 2
		fmt.Println("Tuple enforcement: ALLOW mode — only edge4_allow entries pass (default-deny).")
		fmt.Println("  Ensure KLIQ has populated edge4_allow with frozen edges first!")
		fmt.Println("  Use --feature-profile=graph-enforce to let KLIQ manage the allowlist.")
	default:
		v.Enforce = 0
		fmt.Println("Tuple enforcement: OFF — edge maps loaded but bypassed in XDP.")
	}
	must(m.Update(&k, &v, ebpf.UpdateAny), "update edge4_cfg")
}

/* ---------------- Stats ---------------- */

func sumPerCPU(vals []xdpTotals) xdpTotals {
	var out xdpTotals
	for _, v := range vals {
		out.Pkts += v.Pkts
		out.Bytes += v.Bytes
		out.Pass += v.Pass
		out.DropAllow += v.DropAllow
		out.DropDeny += v.DropDeny
		out.DropRL += v.DropRL
		out.V4 += v.V4
		out.V6 += v.V6
		out.TCP += v.TCP
		out.UDP += v.UDP
		out.ICMP += v.ICMP
		out.SYN += v.SYN
		out.SYNACK += v.SYNACK
		out.RST += v.RST
		out.ACK += v.ACK
		out.IPv4Frags += v.IPv4Frags
		out.DportChg += v.DportChg
		out.NewSources += v.NewSources
		out.AllowHits += v.AllowHits
		out.DenyHits += v.DenyHits
		out.RLHits += v.RLHits
	}
	return out
}

func readTotals() xdpTotals {
	m, err := openPinnedMap(pinTotals)
	must(err, "open totals")
	defer m.Close()

	var k uint32 = 0
	var perCPU []xdpTotals
	must(m.Lookup(&k, &perCPU), "lookup totals per-cpu")

	return sumPerCPU(perCPU)
}

func stats() {
	t := readTotals()
	fmt.Println("=== XDP Totals ===")
	fmt.Printf("pkts=%d bytes=%d pass=%d drop_allow=%d drop_deny=%d drop_rl=%d\n",
		t.Pkts, t.Bytes, t.Pass, t.DropAllow, t.DropDeny, t.DropRL)
	fmt.Printf("v4=%d v6=%d tcp=%d udp=%d icmp=%d syn=%d synack=%d ack=%d rst=%d\n",
		t.V4, t.V6, t.TCP, t.UDP, t.ICMP, t.SYN, t.SYNACK, t.ACK, t.RST)
	fmt.Printf("ipv4_frags=%d dport_changes=%d new_sources=%d allow_hits=%d deny_hits=%d rl_hits=%d\n",
		t.IPv4Frags, t.DportChg, t.NewSources, t.AllowHits, t.DenyHits, t.RLHits)
}

/* ---------------- Top Sources (v4) ---------------- */

type topEntry struct {
	IP        string
	Pkts      uint64
	Bytes     uint64
	DropAllow uint64
	DropDeny  uint64
	DropRL    uint64
	LastNs    uint64
	FirstNs   uint64
}

func topSrc(n int, by string) {
	m, err := openPinnedMap(pinSrc4Stats)
	must(err, "open src4 stats")
	defer m.Close()

	boot := approxBootTime()

	it := m.Iterate()
	var k [4]byte
	var v src4Stats

	out := make([]topEntry, 0, n)

	for it.Next(&k, &v) {
		ip := net.IPv4(k[0], k[1], k[2], k[3]).String()
		out = append(out, topEntry{
			IP:        ip,
			Pkts:      v.Pkts,
			Bytes:     v.Bytes,
			DropAllow: v.DropAllow,
			DropDeny:  v.DropDeny,
			DropRL:    v.DropRL,
			LastNs:    v.LastSeenNs,
			FirstNs:   v.FirstSeenNs,
		})
	}
	if err := it.Err(); err != nil {
		fmt.Printf("iterate src4 error: %v\n", err)
	}

	sort.Slice(out, func(i, j int) bool {
		switch by {
		case "bytes":
			return out[i].Bytes > out[j].Bytes
		case "droprl":
			return out[i].DropRL > out[j].DropRL
		case "drops":
			return (out[i].DropAllow + out[i].DropDeny + out[i].DropRL) > (out[j].DropAllow + out[j].DropDeny + out[j].DropRL)
		default:
			return out[i].Pkts > out[j].Pkts
		}
	})

	if n > len(out) {
		n = len(out)
	}

	fmt.Printf("=== Top %d src4 by %s ===\n", n, by)
	for i := 0; i < n; i++ {
		e := out[i]
		last := boot.Add(time.Duration(e.LastNs)).Format(time.RFC3339Nano)
		first := boot.Add(time.Duration(e.FirstNs)).Format(time.RFC3339Nano)
		fmt.Printf("%2d) %-15s pkts=%d bytes=%d drop_allow=%d drop_deny=%d drop_rl=%d last=%s first=%s\n",
			i+1, e.IP, e.Pkts, e.Bytes, e.DropAllow, e.DropDeny, e.DropRL, last, first)
	}
}

/* ---------------- Events ---------------- */

func events() {
	m, err := openPinnedMap(pinEvents)
	must(err, "open kernloom_events ringbuf")
	defer m.Close()

	rd, err := ringbuf.NewReader(m)
	must(err, "ringbuf reader")
	defer rd.Close()

	boot := approxBootTime()

	fmt.Println("Listening for events (Ctrl+C to stop) ...")
	fmt.Println("Tip: increase event rate with:  sudo ./klshield set-sampling 1")
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		buf := rec.RawSample
		if len(buf) < 44 {
			continue
		}

		var e xdpEvent
		e.TsNs = binary.LittleEndian.Uint64(buf[0:8])
		e.Reason = binary.LittleEndian.Uint32(buf[8:12])
		e.IPVer = buf[12]
		e.L4Proto = buf[13]
		e.Dport = binary.BigEndian.Uint16(buf[14:16])
		copy(e.SaddrV4[:], buf[16:20])
		copy(e.SaddrV6[:], buf[20:36])
		e.PktLen = binary.LittleEndian.Uint32(buf[36:40])
		e.Aux = binary.LittleEndian.Uint32(buf[40:44])

		when := boot.Add(time.Duration(e.TsNs)).Format(time.RFC3339Nano)
		reason := map[uint32]string{1: "DROP_ALLOW", 2: "DROP_DENY", 3: "DROP_RL", 4: "SCAN_HINT"}[e.Reason]

		var src string
		if e.IPVer == 4 {
			src = net.IPv4(e.SaddrV4[0], e.SaddrV4[1], e.SaddrV4[2], e.SaddrV4[3]).String()
		} else {
			src = net.IP(e.SaddrV6[:]).String()
		}

		fmt.Printf("%s %s ipver=%d proto=%d src=%s dport=%d len=%d aux=%d\n",
			when, reason, e.IPVer, e.L4Proto, src, e.Dport, e.PktLen, e.Aux)
	}
}

/* ---------------- CLI ---------------- */

func usage() {
	fmt.Print(`klshield — Kernloom Shield (XDP)

ATTACH / DETACH
  attach-xdp   -iface <iface> [-obj <bpf.o>] [-force]
  detach-xdp   [-iface <iface>]   (auto-detects when only one interface is attached)
  status        overview: XDP state, RL config, deny counts, tuple mode

SOURCE ALLOW / DENY  (CIDR allowlist and per-IP blocklist)
  add-allow-cidr  <cidr>        add to XDP source allowlist (enforce-allow must be on)
  list-allow
  add-deny-ip     <ip>          block source IP immediately in XDP
  del-deny-ip     <ip>
  list-deny
  enforce-allow   on|off        drop all traffic NOT in allowlist (source level)

RATE LIMITING  (default XDP token bucket — no KLIQ needed)
  set-default-rl   -rate <pps> -burst <n>    global rate limit applied to every source
  disable-default-rl                          clear global rate limit
  rl-set-ip        -rate <pps> -burst <n> <ip>  per-source override
  rl-unset-ip      <ip>
  list-rl

TUPLE ENFORCEMENT  (edge-level; requires Shield reload with edge map support)
  Two modes:
    on     — deny-mode (blacklist): denied tuples dropped; first violation packet
             passes through (~1s), then KLIQ writes the deny entry.
    allow  — allow-mode (default-deny): ONLY allowlisted tuples pass; unknown
             tuples dropped immediately with no race window. Activate AFTER
             populating edge4_allow with all frozen edges (see below).
    off    — bypass edge maps entirely (default)

  tuple-enforce    on|off|allow

  Deny-mode management (blacklist):
    add-edge-deny   -src <ip> -port <n> -proto tcp|udp|icmp
    del-edge-deny   -src <ip> -port <n> -proto tcp|udp|icmp
    list-edge-deny

  Allow-mode management (whitelist / default-deny):
    add-edge-allow  -src <ip> -port <n> -proto tcp|udp|icmp
    del-edge-allow  -src <ip> -port <n> -proto tcp|udp|icmp
    list-edge-allow

  Per-tuple rate limiting (both modes):
    set-edge-rl     -src <ip> -port <n> -proto tcp|udp|icmp -rate <pps> -burst <n>

MISC
  set-sampling  <mask>    event ring sampling (0=off, 1=~1/2, 1023=~1/1024)
  reset                   clear all deny and rate-limit entries
  stats                   XDP packet/drop counters
  top-src       [-n 20] [-by pkts|bytes|drops|droprl]
  events                  live event stream from XDP ringbuf
`)
}

// showStatus prints a quick operational overview of the XDP program.
func showStatus() {
	fmt.Println("=== Kernloom Shield status ===")

	// XDP link(s)
	attached := listAttachedIfaces()
	if len(attached) == 0 {
		fmt.Println("XDP:      NOT attached")
	}
	for _, iface := range attached {
		if iface == "(legacy)" {
			fmt.Printf("XDP:      attached (legacy link at %s)\n", pinXdpLinkLegacy)
		} else {
			fmt.Printf("XDP:      attached to %s (link at %s)\n", iface, xdpLinkPin(iface))
		}
	}

	// Default RL
	if m, err := openPinnedMap(pinRLCfg); err == nil {
		defer m.Close()
		var k uint32 = 0
		var v rlCfg
		if err := m.Lookup(&k, &v); err == nil && v.RatePPS > 0 {
			fmt.Printf("Default RL: rate=%d pps  burst=%d pkts\n", v.RatePPS, v.Burst)
		} else {
			fmt.Println("Default RL: disabled")
		}
	}

	// Deny counts
	deny4n, deny6n := 0, 0
	if m, err := openPinnedMap(pinDeny4Hash); err == nil {
		it := m.Iterate()
		var k key4Bytes
		var v uint8
		for it.Next(&k, &v) {
			deny4n++
		}
		m.Close()
	}
	if m, err := openPinnedMap(pinDeny6Hash); err == nil {
		it := m.Iterate()
		var k key6Bytes
		var v uint8
		for it.Next(&k, &v) {
			deny6n++
		}
		m.Close()
	}
	fmt.Printf("Deny entries: v4=%d  v6=%d\n", deny4n, deny6n)

	// Allow enforce
	if m, err := openPinnedMap(pinCfg); err == nil {
		defer m.Close()
		var k uint32 = 0
		var cur xdpCfg
		if err := m.Lookup(&k, &cur); err == nil {
			if cur.EnforceAllow == 1 {
				fmt.Println("Allow-list enforcement: ON")
			} else {
				fmt.Println("Allow-list enforcement: off")
			}
		}
	}

	// Tuple enforcement
	if m, err := openPinnedMap(pinEdge4Cfg); err == nil {
		defer m.Close()
		var k uint32 = 0
		var v edge4CfgValue
		if err := m.Lookup(&k, &v); err == nil {
			switch v.Enforce {
			case 1:
				fmt.Println("Tuple enforcement: DENY mode (blacklist — first violation passes, then blocked)")
			case 2:
				fmt.Println("Tuple enforcement: ALLOW mode (default-deny — unknown tuples blocked immediately)")
			default:
				fmt.Println("Tuple enforcement: off (maps loaded, XDP bypass active)")
			}
		}
	} else {
		fmt.Println("Tuple enforcement: not available (reload Shield with new .bpf.o)")
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "status":
		showStatus()

	case "attach-xdp":
		fs := flag.NewFlagSet("attach-xdp", flag.ExitOnError)
		iface := fs.String("iface", "eth0", "interface")
		obj := fs.String("obj", "bpf/out/xdp_kernloom_shield.bpf.o", "bpf object path")
		force := fs.Bool("force", false, "detach any existing XDP program from iface before attach (WARNING)")
		_ = fs.Parse(os.Args[2:])
		args := fs.Args()
		if len(args) >= 1 {
			*iface = args[0]
		}
		attachXDP(*iface, *obj, *force)

	case "detach-xdp":
		fs := flag.NewFlagSet("detach-xdp", flag.ExitOnError)
		iface := fs.String("iface", "", "interface to detach (auto-detects when only one is attached)")
		_ = fs.Parse(os.Args[2:])
		detachXDP(*iface)

	case "add-allow-cidr":
		if len(os.Args) < 3 {
			must(errors.New("missing cidr"), "add-allow-cidr")
		}
		addAllowCIDR(os.Args[2])

	case "list-allow":
		listAllow()

	case "add-deny-ip":
		if len(os.Args) < 3 {
			must(errors.New("missing ip"), "add-deny-ip")
		}
		addDenyIP(os.Args[2])

	case "del-deny-ip":
		if len(os.Args) < 3 {
			must(errors.New("missing ip"), "del-deny-ip")
		}
		delDenyIP(os.Args[2])

	case "list-deny":
		listDeny()

	case "enforce-allow":
		if len(os.Args) < 3 {
			must(errors.New("missing on|off"), "enforce-allow")
		}
		on := strings.ToLower(os.Args[2]) == "on"
		enforceAllow(on)

	case "set-sampling":
		if len(os.Args) < 3 {
			must(errors.New("missing mask"), "set-sampling")
		}
		var mask uint32
		_, err := fmt.Sscanf(os.Args[2], "%d", &mask)
		must(err, "parse mask")
		setEventSampling(mask)

	case "set-default-rl":
		// Sprint 7: clean alias for rl-set — sets the global per-source token bucket.
		// Every new source is immediately subject to this limit in XDP, without
		// waiting for KLIQ to react. KLIQ can still apply stricter per-IP overrides.
		fs := flag.NewFlagSet("set-default-rl", flag.ExitOnError)
		rate := fs.Uint64("rate", 0, "packets/sec limit applied to every source")
		burst := fs.Uint64("burst", 0, "burst allowance in packets")
		_ = fs.Parse(os.Args[2:])
		if *rate == 0 || *burst == 0 {
			fmt.Fprintln(os.Stderr, "usage: klshield set-default-rl -rate <pps> -burst <n>")
			os.Exit(1)
		}
		rlSet(*rate, *burst)
		fmt.Printf("Default RL active: every source is limited to %d pps (burst %d) in XDP.\n", *rate, *burst)

	case "disable-default-rl":
		// Sprint 7: clear the global rate limit (rate=0 disables the token bucket).
		rlSet(0, 0)
		fmt.Println("Default RL disabled.")

	case "rl-set":
		fs := flag.NewFlagSet("rl-set", flag.ExitOnError)
		rate := fs.Uint64("rate", 0, "tokens/sec (pps)")
		burst := fs.Uint64("burst", 0, "max tokens")
		_ = fs.Parse(os.Args[2:])
		rlSet(*rate, *burst)

	case "rl-set-ip":
		fs := flag.NewFlagSet("rl-set-ip", flag.ExitOnError)
		rate := fs.Uint64("rate", 0, "tokens/sec (pps)")
		burst := fs.Uint64("burst", 0, "max tokens")
		_ = fs.Parse(os.Args[2:])
		args := fs.Args()
		if len(args) < 1 {
			must(errors.New("missing ip"), "rl-set-ip")
		}
		rlSetIP(args[0], *rate, *burst)

	case "rl-unset-ip":
		if len(os.Args) < 3 {
			must(errors.New("missing ip"), "rl-unset-ip")
		}
		rlUnsetIP(os.Args[2])

	case "list-rl":
		listRL()

	case "tuple-enforce":
		if len(os.Args) < 3 {
			must(fmt.Errorf("missing on|off|allow"), "tuple-enforce")
		}
		tupleEnforceMode(os.Args[2])

	case "add-edge-deny":
		fs := flag.NewFlagSet("add-edge-deny", flag.ExitOnError)
		src := fs.String("src", "", "source IP")
		port := fs.String("port", "", "destination port")
		proto := fs.String("proto", "tcp", "tcp|udp|icmp")
		_ = fs.Parse(os.Args[2:])
		mustIf(*src == "" || *port == "", "add-edge-deny requires -src, -port")
		addEdgeDeny(*src, *port, *proto)

	case "del-edge-deny":
		fs := flag.NewFlagSet("del-edge-deny", flag.ExitOnError)
		src := fs.String("src", "", "source IP")
		port := fs.String("port", "", "destination port")
		proto := fs.String("proto", "tcp", "tcp|udp|icmp")
		_ = fs.Parse(os.Args[2:])
		mustIf(*src == "" || *port == "", "del-edge-deny requires -src, -port")
		delEdgeDeny(*src, *port, *proto)

	case "list-edge-deny":
		listEdgeDeny()

	case "add-edge-allow":
		fs := flag.NewFlagSet("add-edge-allow", flag.ExitOnError)
		src := fs.String("src", "", "source IP")
		port := fs.String("port", "", "destination port")
		proto := fs.String("proto", "tcp", "tcp|udp|icmp")
		_ = fs.Parse(os.Args[2:])
		mustIf(*src == "" || *port == "", "add-edge-allow requires -src, -port")
		addEdgeAllow(*src, *port, *proto)

	case "del-edge-allow":
		fs := flag.NewFlagSet("del-edge-allow", flag.ExitOnError)
		src := fs.String("src", "", "source IP")
		port := fs.String("port", "", "destination port")
		proto := fs.String("proto", "tcp", "tcp|udp|icmp")
		_ = fs.Parse(os.Args[2:])
		mustIf(*src == "" || *port == "", "del-edge-allow requires -src, -port")
		delEdgeAllow(*src, *port, *proto)

	case "list-edge-allow":
		listEdgeAllow()

	case "set-edge-rl":
		fs := flag.NewFlagSet("set-edge-rl", flag.ExitOnError)
		src := fs.String("src", "", "source IP")
		port := fs.String("port", "", "destination port")
		proto := fs.String("proto", "tcp", "tcp|udp|icmp")
		rate := fs.Uint64("rate", 0, "packets/sec")
		burst := fs.Uint64("burst", 0, "burst size")
		_ = fs.Parse(os.Args[2:])
		mustIf(*src == "" || *port == "" || *rate == 0 || *burst == 0,
			"set-edge-rl requires -src, -port, -rate, -burst")
		setEdgeRL(*src, *port, *proto, *rate, *burst)

	case "reset":
		resetMaps()

	case "stats":
		stats()

	case "top-src":
		fs := flag.NewFlagSet("top-src", flag.ExitOnError)
		n := fs.Int("n", 20, "top N")
		by := fs.String("by", "pkts", "pkts|bytes|drops|droprl")
		_ = fs.Parse(os.Args[2:])
		topSrc(*n, *by)

	case "events":
		events()

	default:
		usage()
		os.Exit(1)
	}
}
