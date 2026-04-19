package store

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// entry holds a session value and its expiry
type entry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

func (e *entry) expired() bool {
	return !e.expiresAt.IsZero() && time.Now().After(e.expiresAt)
}

// shard is one partition of the store, independently locked
type shard struct {
	mu   sync.RWMutex
	data map[string]*entry
}

// Store is a sharded, concurrent, TTL-aware in-memory key-value store
type Store struct {
	shards        []*shard
	shardCount    uint32
	defaultTTL    time.Duration
	maxTTL        time.Duration
	maxKeys       int
	totalKeys     atomic.Int64
	sweepInterval time.Duration
	stopSweep     chan struct{}

	// Stats
	hits   atomic.Int64
	misses atomic.Int64
	sets   atomic.Int64
	dels   atomic.Int64
}

// New creates a new Store and starts the background TTL sweeper
func New(shardCount int, defaultTTL, maxTTL, sweepInterval time.Duration, maxKeys int) *Store {
	if shardCount <= 0 {
		shardCount = 256
	}
	shards := make([]*shard, shardCount)
	for i := range shards {
		shards[i] = &shard{data: make(map[string]*entry)}
	}

	s := &Store{
		shards:        shards,
		shardCount:    uint32(shardCount),
		defaultTTL:    defaultTTL,
		maxTTL:        maxTTL,
		maxKeys:       maxKeys,
		sweepInterval: sweepInterval,
		stopSweep:     make(chan struct{}),
	}
	go s.sweeper()
	return s
}

// getShard returns the shard responsible for key
func (s *Store) getShard(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return s.shards[h.Sum32()%s.shardCount]
}

// Set stores key=value with optional TTL.
// ttl=0 means use the server default TTL.
// ttl<0 means no expiry (persistent).
func (s *Store) Set(key string, value []byte, ttl time.Duration) bool {
	// Enforce max keys
	if s.maxKeys > 0 && s.totalKeys.Load() >= int64(s.maxKeys) {
		return false
	}

	// Resolve TTL
	if ttl == 0 {
		ttl = s.defaultTTL
	}
	if s.maxTTL > 0 && ttl > s.maxTTL {
		ttl = s.maxTTL
	}

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	sh := s.getShard(key)
	sh.mu.Lock()
	_, existed := sh.data[key]
	sh.data[key] = &entry{value: value, expiresAt: exp}
	sh.mu.Unlock()

	if !existed {
		s.totalKeys.Add(1)
	}
	s.sets.Add(1)
	return true
}

// SetNX sets key only if it doesn't exist. Returns true if set.
func (s *Store) SetNX(key string, value []byte, ttl time.Duration) bool {
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	existing, ok := sh.data[key]
	if ok && !existing.expired() {
		return false
	}

	if ttl == 0 {
		ttl = s.defaultTTL
	}
	if s.maxTTL > 0 && ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	sh.data[key] = &entry{value: value, expiresAt: exp}
	if !ok {
		s.totalKeys.Add(1)
	}
	s.sets.Add(1)
	return true
}

// Get retrieves a value. Returns nil if missing or expired.
func (s *Store) Get(key string) []byte {
	sh := s.getShard(key)
	sh.mu.RLock()
	e, ok := sh.data[key]
	sh.mu.RUnlock()

	if !ok || e.expired() {
		s.misses.Add(1)
		if ok && e.expired() {
			s.Delete(key)
		}
		return nil
	}
	s.hits.Add(1)
	return e.value
}

// Delete removes a key. Returns true if it existed.
func (s *Store) Delete(keys ...string) int {
	deleted := 0
	for _, key := range keys {
		sh := s.getShard(key)
		sh.mu.Lock()
		if _, ok := sh.data[key]; ok {
			delete(sh.data, key)
			s.totalKeys.Add(-1)
			deleted++
			s.dels.Add(1)
		}
		sh.mu.Unlock()
	}
	return deleted
}

// Exists returns how many of the given keys exist and are not expired
func (s *Store) Exists(keys ...string) int {
	count := 0
	for _, key := range keys {
		sh := s.getShard(key)
		sh.mu.RLock()
		e, ok := sh.data[key]
		sh.mu.RUnlock()
		if ok && !e.expired() {
			count++
		}
	}
	return count
}

// Expire sets or updates TTL on an existing key. Returns true if key existed.
func (s *Store) Expire(key string, ttl time.Duration) bool {
	if s.maxTTL > 0 && ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e, ok := sh.data[key]
	if !ok || e.expired() {
		return false
	}
	e.expiresAt = time.Now().Add(ttl)
	return true
}

// TTL returns remaining time for a key. -1 = no expiry, -2 = not found/expired.
func (s *Store) TTL(key string) time.Duration {
	sh := s.getShard(key)
	sh.mu.RLock()
	e, ok := sh.data[key]
	sh.mu.RUnlock()

	if !ok || e.expired() {
		return -2
	}
	if e.expiresAt.IsZero() {
		return -1
	}
	remaining := time.Until(e.expiresAt)
	if remaining < 0 {
		return -2
	}
	return remaining
}

// FlushAll removes all keys
func (s *Store) FlushAll() {
	for _, sh := range s.shards {
		sh.mu.Lock()
		sh.data = make(map[string]*entry)
		sh.mu.Unlock()
	}
	s.totalKeys.Store(0)
}

// Len returns total number of non-expired keys (approximate)
func (s *Store) Len() int64 {
	return s.totalKeys.Load()
}

// Stats returns hit/miss/set/del counters
func (s *Store) Stats() (hits, misses, sets, dels int64) {
	return s.hits.Load(), s.misses.Load(), s.sets.Load(), s.dels.Load()
}

// sweeper periodically removes expired keys from all shards
func (s *Store) sweeper() {
	ticker := time.NewTicker(s.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweep()
		case <-s.stopSweep:
			return
		}
	}
}

func (s *Store) sweep() {
	for _, sh := range s.shards {
		sh.mu.Lock()
		for k, e := range sh.data {
			if e.expired() {
				delete(sh.data, k)
				s.totalKeys.Add(-1)
			}
		}
		sh.mu.Unlock()
	}
}

// Close stops the background sweeper
func (s *Store) Close() {
	close(s.stopSweep)
}
