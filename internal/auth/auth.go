package auth

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// rule is a single allowlist entry — either an exact IP or a CIDR network
type rule struct {
	raw     string
	network *net.IPNet // non-nil for CIDR
	ip      net.IP     // non-nil for exact IP
}

func parseRule(s string) (rule, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		// CIDR range: "192.168.1.0/24"
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return rule{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return rule{raw: s, network: network}, nil
	}
	// Plain IP: "192.168.1.5" or "::1"
	ip := net.ParseIP(s)
	if ip == nil {
		return rule{}, fmt.Errorf("invalid IP %q", s)
	}
	return rule{raw: s, ip: ip}, nil
}

func (r rule) matches(ip net.IP) bool {
	if r.network != nil {
		return r.network.Contains(ip)
	}
	return r.ip.Equal(ip)
}

// Manager handles authentication and IP allowlisting
type Manager struct {
	password    string
	requireAuth bool
	rules       []rule
	mu          sync.RWMutex
}

// New creates an auth Manager.
// allowedIPs entries may be plain IPs ("10.0.0.1") or CIDRs ("10.0.0.0/24").
// An empty allowedIPs slice means ALL IPs are permitted.
func New(password string, requireAuth bool, allowedIPs []string) *Manager {
	m := &Manager{
		password:    password,
		requireAuth: requireAuth,
	}
	for _, raw := range allowedIPs {
		r, err := parseRule(raw)
		if err != nil {
			fmt.Printf("[auth] WARNING: skipping invalid allowlist entry %q: %v\n", raw, err)
			continue
		}
		m.rules = append(m.rules, r)
	}
	return m
}

// IsIPAllowed returns true if the remote address is permitted.
// If the allowlist is empty, every address is allowed. Otherwise the remote
// IP must match at least one rule — loopback has no implicit exception.
func (m *Manager) IsIPAllowed(remoteAddr string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.rules) == 0 {
		return true // open access — no allowlist configured
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// remoteAddr may already be a plain IP (e.g. from tests)
		host = remoteAddr
	}

	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		fmt.Printf("[auth] WARNING: cannot parse remote IP %q — denying\n", remoteAddr)
		return false
	}

	for _, r := range m.rules {
		if r.matches(ip) {
			return true
		}
	}
	return false
}

// CheckPassword validates the AUTH password
func (m *Manager) CheckPassword(pw string) bool {
	if !m.requireAuth {
		return true
	}
	return pw == m.password
}

// RequiresAuth returns whether authentication is required
func (m *Manager) RequiresAuth() bool {
	return m.requireAuth
}

// AllowlistSummary returns a human-readable list of allowed entries
func (m *Manager) AllowlistSummary() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.rules) == 0 {
		return "<all IPs allowed>"
	}
	parts := make([]string, len(m.rules))
	for i, r := range m.rules {
		parts[i] = r.raw
	}
	return strings.Join(parts, ", ")
}
