package rg

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

func NormalizeIP(raw string) (string, error) {
	text := strings.TrimSpace(raw)
	if i := strings.IndexByte(text, '%'); i >= 0 {
		text = text[:i]
	}
	ip := net.ParseIP(text)
	if ip == nil {
		return "", fmt.Errorf("bad ip")
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), nil
	}
	return ip.String(), nil
}

func IsPublic(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}
	return true
}

func NormalizeMAC(raw string) string {
	text := strings.ToLower(strings.TrimSpace(raw))
	text = strings.ReplaceAll(text, "-", ":")
	parts := strings.Split(text, ":")
	if len(parts) != 6 {
		return ""
	}
	var nums [6]int
	for i, part := range parts {
		if part == "" || len(part) > 2 {
			return ""
		}
		n := 0
		for _, c := range part {
			n *= 16
			switch {
			case c >= '0' && c <= '9':
				n += int(c - '0')
			case c >= 'a' && c <= 'f':
				n += int(c-'a') + 10
			default:
				return ""
			}
		}
		if n > 0xff {
			return ""
		}
		nums[i] = n
	}
	all0, allF := true, true
	for _, n := range nums {
		if n != 0 {
			all0 = false
		}
		if n != 0xff {
			allF = false
		}
	}
	if all0 || allF {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", nums[0], nums[1], nums[2], nums[3], nums[4], nums[5])
}

func MacKey(mac string) string { return "mac:" + mac }

func NormalizeCountry(raw string) string {
	text := strings.ToUpper(strings.TrimSpace(raw))
	if len(text) != 2 || !isAlpha(text) {
		return ""
	}
	return text
}

var arpAt = regexp.MustCompile(`(?i)\(([^)]+)\)\s+at\s+(\S+)`)

type neighbors struct {
	mu      sync.Mutex
	loaded  time.Time
	entries map[string]string
}

var neighborCache neighbors

func LinkAddress(ip string) string {
	key, err := NormalizeIP(ip)
	if err != nil {
		return ""
	}
	neighborCache.mu.Lock()
	if time.Since(neighborCache.loaded) < time.Second && neighborCache.entries != nil {
		mac := neighborCache.entries[key]
		neighborCache.mu.Unlock()
		return mac
	}
	neighborCache.mu.Unlock()
	entries := loadNeighbors()
	neighborCache.mu.Lock()
	neighborCache.entries = entries
	neighborCache.loaded = time.Now()
	mac := entries[key]
	neighborCache.mu.Unlock()
	return mac
}

func loadNeighbors() map[string]string {
	found := map[string]string{}
	proc, _ := os.ReadFile("/proc/net/arp")
	if len(proc) > 0 {
		parseProcARP(string(proc), found)
		parseIPNeigh(runCmd("ip", "neigh", "show"), found)
		return found
	}
	parseARPAN(runCmd("arp", "-an"), found)
	parseNDP(runCmd("ndp", "-an"), found)
	parseIPNeigh(runCmd("ip", "neigh", "show"), found)
	return found
}

func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	timer := time.AfterFunc(500*time.Millisecond, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

func putMAC(found map[string]string, rawIP, rawMAC string) {
	mac := NormalizeMAC(rawMAC)
	if mac == "" {
		return
	}
	ip, err := NormalizeIP(rawIP)
	if err != nil {
		return
	}
	found[ip] = mac
}

func parseProcARP(text string, found map[string]string) {
	sc := bufio.NewScanner(strings.NewReader(text))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		parts := strings.Fields(sc.Text())
		if len(parts) < 4 {
			continue
		}
		flags, err := parseHex(parts[2])
		if err != nil || flags&0x2 == 0 {
			continue
		}
		putMAC(found, parts[0], parts[3])
	}
}

func parseIPNeigh(text string, found map[string]string) {
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Fields(line)
		idx := -1
		bad := false
		for i, part := range parts {
			if part == "lladdr" {
				idx = i + 1
			}
			if part == "FAILED" || part == "INCOMPLETE" {
				bad = true
			}
		}
		if bad || idx < 0 || idx >= len(parts) {
			continue
		}
		putMAC(found, parts[0], parts[idx])
	}
}

func parseARPAN(text string, found map[string]string) {
	for _, match := range arpAt.FindAllStringSubmatch(text, -1) {
		putMAC(found, match[1], match[2])
	}
}

func parseNDP(text string, found map[string]string) {
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 || strings.EqualFold(parts[0], "neighbor") {
			continue
		}
		putMAC(found, parts[0], parts[1])
	}
}

func parseHex(raw string) (int, error) {
	n := 0
	for _, c := range strings.TrimPrefix(strings.ToLower(raw), "0x") {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		default:
			return 0, fmt.Errorf("bad hex")
		}
	}
	return n, nil
}

func InterfaceIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var v4, v6 []string
	seen := map[string]struct{}{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			ip := ipnet.IP
			if !usableIP(ip) {
				continue
			}
			text := ip.String()
			if v4ip := ip.To4(); v4ip != nil {
				text = v4ip.String()
			}
			if _, ok := seen[text]; ok {
				continue
			}
			seen[text] = struct{}{}
			if strings.Contains(text, ":") {
				v6 = append(v6, text)
			} else {
				v4 = append(v4, text)
			}
		}
	}
	return append(v4, v6...)
}

func usableIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] >= 240 {
		return false
	}
	return true
}
