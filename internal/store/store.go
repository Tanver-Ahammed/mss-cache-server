package store

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// entry holds a session value and its expiry
type entry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

func (e *entry) expired() bool {
	return !e.expiresAt.IsZero() && time.Now().After(e.expiresAt)
}

// hashEntry holds a hash field value and its expiry
type hashEntry struct {
	fields    map[string][]byte
	expiresAt time.Time // zero = no expiry
}

func (h *hashEntry) expired() bool {
	return !h.expiresAt.IsZero() && time.Now().After(h.expiresAt)
}

// shard is one partition of the store, independently locked
type shard struct {
	mu     sync.RWMutex
	data   map[string]*entry
	hashes map[string]*hashEntry
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

	// OnExpiry is called by the sweeper with expired keys for persistence cleanup
	OnExpiry func(keys []string)
}

// New creates a new Store and starts the background TTL sweeper
func New(shardCount int, defaultTTL, maxTTL, sweepInterval time.Duration, maxKeys int) *Store {
	if shardCount <= 0 {
		shardCount = 256
	}
	shards := make([]*shard, shardCount)
	for i := range shards {
		shards[i] = &shard{
			data:   make(map[string]*entry),
			hashes: make(map[string]*hashEntry),
		}
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
		if _, ok := sh.hashes[key]; ok {
			delete(sh.hashes, key)
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
		e, eok := sh.data[key]
		h, hok := sh.hashes[key]
		sh.mu.RUnlock()
		if (eok && !e.expired()) || (hok && !h.expired()) {
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
	t := time.Now().Add(ttl)
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.data[key]; ok && !e.expired() {
		e.expiresAt = t
		return true
	}
	if h, ok := sh.hashes[key]; ok && !h.expired() {
		h.expiresAt = t
		return true
	}
	return false
}

// ExpireAt sets expiry to an absolute Unix timestamp (seconds)
func (s *Store) ExpireAt(key string, unixSec int64) bool {
	t := time.Unix(unixSec, 0)
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.data[key]; ok && !e.expired() {
		e.expiresAt = t
		return true
	}
	if h, ok := sh.hashes[key]; ok && !h.expired() {
		h.expiresAt = t
		return true
	}
	return false
}

// PExpireAt sets expiry to an absolute Unix timestamp (milliseconds) — works on strings and hashes
func (s *Store) PExpireAt(key string, unixMs int64) bool {
	t := time.UnixMilli(unixMs)
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.data[key]; ok && !e.expired() {
		e.expiresAt = t
		return true
	}
	if h, ok := sh.hashes[key]; ok && !h.expired() {
		h.expiresAt = t
		return true
	}
	return false
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
		sh.hashes = make(map[string]*hashEntry)
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
	var expired []string
	for _, sh := range s.shards {
		sh.mu.Lock()
		for k, e := range sh.data {
			if e.expired() {
				delete(sh.data, k)
				s.totalKeys.Add(-1)
				expired = append(expired, k)
			}
		}
		for k, h := range sh.hashes {
			if h.expired() {
				delete(sh.hashes, k)
				s.totalKeys.Add(-1)
				expired = append(expired, k)
			}
		}
		sh.mu.Unlock()
	}
	if len(expired) > 0 && s.OnExpiry != nil {
		s.OnExpiry(expired)
	}
}

// ─── Hash Commands ────────────────────────────────────────────────────────────

// HMSet merges multiple hash fields into an existing hash (or creates it).
func (s *Store) HMSet(key string, fields map[string][]byte, ttl time.Duration) bool {
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	h, existed := sh.hashes[key]
	if !existed {
		if s.maxKeys > 0 && s.totalKeys.Load() >= int64(s.maxKeys) {
			return false
		}
		h = &hashEntry{fields: make(map[string][]byte)}
		sh.hashes[key] = h
		s.totalKeys.Add(1)
	}

	// Merge: update only provided fields, preserve existing ones
	for k, v := range fields {
		h.fields[k] = v
	}

	// Only set TTL when creating a new key; HMSET on an existing key preserves TTL
	if !existed && ttl != 0 {
		if s.maxTTL > 0 && ttl > s.maxTTL {
			ttl = s.maxTTL
		}
		h.expiresAt = time.Now().Add(ttl)
	}
	return true
}

// HGetAll retrieves all fields of a hash
func (s *Store) HGetAll(key string) map[string][]byte {
	sh := s.getShard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	h, ok := sh.hashes[key]
	if !ok || h.expired() {
		if ok && h.expired() {
			sh.mu.RUnlock()
			sh.mu.Lock()
			delete(sh.hashes, key)
			s.totalKeys.Add(-1)
			sh.mu.Unlock()
			sh.mu.RLock()
		}
		return nil
	}

	// Return a copy to avoid external mutation
	result := make(map[string][]byte, len(h.fields))
	for k, v := range h.fields {
		result[k] = v
	}
	return result
}

// HGet retrieves a single hash field
func (s *Store) HGet(key, field string) []byte {
	sh := s.getShard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	h, ok := sh.hashes[key]
	if !ok || h.expired() {
		return nil
	}
	return h.fields[field]
}

// HDel deletes hash fields
func (s *Store) HDel(key string, fields ...string) int {
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	h, ok := sh.hashes[key]
	if !ok || h.expired() {
		return 0
	}

	count := 0
	for _, f := range fields {
		if _, exists := h.fields[f]; exists {
			delete(h.fields, f)
			count++
		}
	}

	// If hash is now empty, remove the key
	if len(h.fields) == 0 {
		delete(sh.hashes, key)
		s.totalKeys.Add(-1)
	}

	return count
}

// HLen returns number of fields in a hash
func (s *Store) HLen(key string) int {
	sh := s.getShard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	h, ok := sh.hashes[key]
	if !ok || h.expired() {
		return 0
	}
	return len(h.fields)
}

// HExists checks if a field exists in a hash
func (s *Store) HExists(key, field string) bool {
	sh := s.getShard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	h, ok := sh.hashes[key]
	if !ok || h.expired() {
		return false
	}
	_, exists := h.fields[field]
	return exists
}

// Type returns the type of a key: "string", "hash", or "none"
func (s *Store) Type(key string) string {
	sh := s.getShard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	if e, ok := sh.data[key]; ok && !e.expired() {
		return "string"
	}
	if h, ok := sh.hashes[key]; ok && !h.expired() {
		return "hash"
	}
	return "none"
}

// AllKeys returns all non-expired keys (both strings and hashes)
func (s *Store) AllKeys() []string {
	var keys []string
	for _, sh := range s.shards {
		sh.mu.RLock()
		for k, e := range sh.data {
			if !e.expired() {
				keys = append(keys, k)
			}
		}
		for k, h := range sh.hashes {
			if !h.expired() {
				keys = append(keys, k)
			}
		}
		sh.mu.RUnlock()
	}
	return keys
}

// Rename renames a key. Returns true if successful, false if old key doesn't exist.
func (s *Store) Rename(oldKey, newKey string) bool {
	if oldKey == newKey {
		return s.Exists(oldKey) == 1
	}

	oldSh := s.getShard(oldKey)
	newSh := s.getShard(newKey)

	// Lock order: lowest address first to avoid deadlock
	if uintptr(unsafe.Pointer(oldSh)) < uintptr(unsafe.Pointer(newSh)) {
		oldSh.mu.Lock()
		newSh.mu.Lock()
	} else {
		newSh.mu.Lock()
		oldSh.mu.Lock()
	}
	defer oldSh.mu.Unlock()
	defer newSh.mu.Unlock()

	// Move string entry
	if e, ok := oldSh.data[oldKey]; ok && !e.expired() {
		newSh.data[newKey] = e
		delete(oldSh.data, oldKey)
		return true
	}

	// Move hash entry
	if h, ok := oldSh.hashes[oldKey]; ok && !h.expired() {
		newSh.hashes[newKey] = h
		delete(oldSh.hashes, oldKey)
		return true
	}

	return false
}

// SetAbs stores key=value with an absolute expiry time (used for DB reload).
// expiresAt.IsZero() means no expiry.
func (s *Store) SetAbs(key string, value []byte, expiresAt time.Time) bool {
	if s.maxKeys > 0 && s.totalKeys.Load() >= int64(s.maxKeys) {
		return false
	}
	sh := s.getShard(key)
	sh.mu.Lock()
	_, existed := sh.data[key]
	sh.data[key] = &entry{value: value, expiresAt: expiresAt}
	sh.mu.Unlock()

	if !existed {
		s.totalKeys.Add(1)
	}
	s.sets.Add(1)
	return true
}

// HMSetAbs stores a hash with an absolute expiry time (used for DB reload).
func (s *Store) HMSetAbs(key string, fields map[string][]byte, expiresAt time.Time) bool {
	sh := s.getShard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	h, existed := sh.hashes[key]
	if !existed {
		if s.maxKeys > 0 && s.totalKeys.Load() >= int64(s.maxKeys) {
			return false
		}
		h = &hashEntry{fields: make(map[string][]byte)}
		sh.hashes[key] = h
		s.totalKeys.Add(1)
	}
	for k, v := range fields {
		h.fields[k] = v
	}
	h.expiresAt = expiresAt
	return true
}

// Close stops the background sweeper
func (s *Store) Close() {
	close(s.stopSweep)
}
