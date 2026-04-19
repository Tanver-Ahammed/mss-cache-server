package store_test

import (
	"testing"
	"time"

	"github.com/yourorg/go-session-server/internal/store"
)

func newStore() *store.Store {
	return store.New(16, 30*time.Minute, 24*time.Hour, 1*time.Minute, 0)
}

func TestSetGet(t *testing.T) {
	s := newStore()
	defer s.Close()

	s.Set("foo", []byte("bar"), 0)
	val := s.Get("foo")
	if string(val) != "bar" {
		t.Fatalf("expected 'bar', got %q", val)
	}
}

func TestTTLExpiry(t *testing.T) {
	s := newStore()
	defer s.Close()

	s.Set("expire-me", []byte("value"), 50*time.Millisecond)
	if s.Get("expire-me") == nil {
		t.Fatal("key should exist before expiry")
	}
	time.Sleep(100 * time.Millisecond)
	if s.Get("expire-me") != nil {
		t.Fatal("key should be expired")
	}
}

func TestDelete(t *testing.T) {
	s := newStore()
	defer s.Close()

	s.Set("a", []byte("1"), 0)
	s.Set("b", []byte("2"), 0)
	n := s.Delete("a", "b", "nonexistent")
	if n != 2 {
		t.Fatalf("expected 2 deleted, got %d", n)
	}
}

func TestSetNX(t *testing.T) {
	s := newStore()
	defer s.Close()

	ok := s.SetNX("nx-key", []byte("first"), 0)
	if !ok {
		t.Fatal("first SetNX should succeed")
	}
	ok = s.SetNX("nx-key", []byte("second"), 0)
	if ok {
		t.Fatal("second SetNX should fail")
	}
	if string(s.Get("nx-key")) != "first" {
		t.Fatal("value should not have changed")
	}
}

func TestMaxTTLCap(t *testing.T) {
	s := store.New(16, 30*time.Minute, 1*time.Second, 1*time.Minute, 0)
	defer s.Close()

	// Request 1 hour TTL, but max is 1 second
	s.Set("capped", []byte("val"), 1*time.Hour)
	time.Sleep(1100 * time.Millisecond)
	if s.Get("capped") != nil {
		t.Fatal("key should have been capped to 1s TTL")
	}
}

func TestExists(t *testing.T) {
	s := newStore()
	defer s.Close()

	s.Set("e1", []byte("v"), 0)
	s.Set("e2", []byte("v"), 0)
	n := s.Exists("e1", "e2", "e3")
	if n != 2 {
		t.Fatalf("expected 2 existing keys, got %d", n)
	}
}

func TestFlushAll(t *testing.T) {
	s := newStore()
	defer s.Close()

	for i := 0; i < 100; i++ {
		s.Set(string(rune('a'+i)), []byte("v"), 0)
	}
	s.FlushAll()
	if s.Len() != 0 {
		t.Fatalf("expected 0 keys after flush, got %d", s.Len())
	}
}

func BenchmarkSet(b *testing.B) {
	s := newStore()
	defer s.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Set("bench-key", []byte("bench-value"), 0)
	}
}

func BenchmarkGet(b *testing.B) {
	s := newStore()
	defer s.Close()
	s.Set("bench-key", []byte("bench-value"), 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Get("bench-key")
	}
}
