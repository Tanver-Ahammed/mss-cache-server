package auth_test

import (
	"testing"

	"github.com/yourorg/go-session-server/internal/auth"
)

func TestExactIPAllow(t *testing.T) {
	m := auth.New("pass", true, []string{"192.168.1.10"})
	if !m.IsIPAllowed("192.168.1.10:12345") {
		t.Error("exact IP should be allowed")
	}
	if m.IsIPAllowed("192.168.1.11:12345") {
		t.Error("different IP should be denied")
	}
}

func TestCIDRAllow(t *testing.T) {
	m := auth.New("pass", true, []string{"10.0.0.0/24"})
	if !m.IsIPAllowed("10.0.0.1:9000") {
		t.Error("IP in CIDR range should be allowed")
	}
	if !m.IsIPAllowed("10.0.0.254:9000") {
		t.Error("IP in CIDR range should be allowed")
	}
	if m.IsIPAllowed("10.0.1.1:9000") {
		t.Error("IP outside CIDR should be denied")
	}
}

func TestMixedRules(t *testing.T) {
	m := auth.New("pass", true, []string{
		"10.0.0.0/24",
		"192.168.5.20",
	})
	if !m.IsIPAllowed("10.0.0.50:1234") {
		t.Error("CIDR match should pass")
	}
	if !m.IsIPAllowed("192.168.5.20:1234") {
		t.Error("exact IP match should pass")
	}
	if m.IsIPAllowed("172.16.0.1:1234") {
		t.Error("unmatched IP should be denied")
	}
}

func TestEmptyAllowlistPermitsAll(t *testing.T) {
	m := auth.New("pass", true, []string{})
	if !m.IsIPAllowed("8.8.8.8:1234") {
		t.Error("empty allowlist should permit all IPs")
	}
}

func TestLoopbackAlwaysAllowed(t *testing.T) {
	// Even with a strict allowlist, loopback should pass
	m := auth.New("pass", true, []string{"10.0.0.1"})
	if !m.IsIPAllowed("127.0.0.1:5678") {
		t.Error("loopback should always be allowed")
	}
}

func TestPasswordCheck(t *testing.T) {
	m := auth.New("secret", true, nil)
	if !m.CheckPassword("secret") {
		t.Error("correct password should pass")
	}
	if m.CheckPassword("wrong") {
		t.Error("wrong password should fail")
	}
}

func TestNoAuthRequired(t *testing.T) {
	m := auth.New("", false, nil)
	if !m.CheckPassword("anything") {
		t.Error("no-auth mode should accept any password")
	}
}
