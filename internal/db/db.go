package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type opKind int

const (
	opSetSession opKind = iota
	opSetHash
	opDeleteKeys
)

type dbOp struct {
	kind      opKind
	key       string
	value     []byte
	fields    map[string][]byte
	keys      []string
	expiresAt time.Time
}

type DB struct {
	pool   *sql.DB
	opCh   chan dbOp
	done   chan struct{}
	closed chan struct{}
}

func New(dsn string, queueDepth int) (*DB, error) {
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	pool.SetMaxOpenConns(4)
	pool.SetMaxIdleConns(2)
	pool.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = pool.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	if err = applySchema(ctx, pool); err != nil {
		return nil, fmt.Errorf("db: schema: %w", err)
	}

	d := &DB{
		pool:   pool,
		opCh:   make(chan dbOp, queueDepth),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	go d.worker()
	return d, nil
}

func applySchema(ctx context.Context, pool *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS sessions (
    key        TEXT        NOT NULL PRIMARY KEY,
    value      BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS session_hashes (
    key        TEXT        NOT NULL PRIMARY KEY,
    fields     JSONB       NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_session_hashes_expires_at
    ON session_hashes (expires_at) WHERE expires_at IS NOT NULL;`
	_, err := pool.ExecContext(ctx, ddl)
	return err
}

func (d *DB) AsyncSetSession(key string, value []byte, expiresAt time.Time) {
	d.enqueue(dbOp{kind: opSetSession, key: key, value: value, expiresAt: expiresAt})
}

func (d *DB) AsyncSetHash(key string, fields map[string][]byte, expiresAt time.Time) {
	cp := make(map[string][]byte, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	d.enqueue(dbOp{kind: opSetHash, key: key, fields: cp, expiresAt: expiresAt})
}

func (d *DB) AsyncDeleteKeys(keys ...string) {
	if len(keys) == 0 {
		return
	}
	d.enqueue(dbOp{kind: opDeleteKeys, keys: keys})
}

func (d *DB) enqueue(op dbOp) {
	select {
	case d.opCh <- op:
	default:
		log.Printf("[db] WARNING: write-behind queue full (%d), dropping op kind=%d key=%s",
			cap(d.opCh), op.kind, op.key)
	}
}

func (d *DB) worker() {
	defer close(d.closed)
	for {
		select {
		case op := <-d.opCh:
			d.execute(op)
		case <-d.done:
			for {
				select {
				case op := <-d.opCh:
					d.execute(op)
				default:
					return
				}
			}
		}
	}
}

func (d *DB) execute(op dbOp) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var err error
	switch op.kind {
	case opSetSession:
		err = d.execSetSession(ctx, op)
	case opSetHash:
		err = d.execSetHash(ctx, op)
	case opDeleteKeys:
		err = d.execDeleteKeys(ctx, op.keys)
	}
	if err != nil {
		log.Printf("[db] ERROR executing op kind=%d key=%s: %v", op.kind, op.key, err)
	}
}

func (d *DB) execSetSession(ctx context.Context, op dbOp) error {
	var expiresAt interface{}
	if !op.expiresAt.IsZero() {
		expiresAt = op.expiresAt.UTC()
	}
	_, err := d.pool.ExecContext(ctx, `
        INSERT INTO sessions (key, value, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (key) DO UPDATE
            SET value      = EXCLUDED.value,
                expires_at = EXCLUDED.expires_at
    `, op.key, op.value, expiresAt)
	return err
}

func (d *DB) execSetHash(ctx context.Context, op dbOp) error {
	jsonFields := make(map[string]string, len(op.fields))
	for k, v := range op.fields {
		jsonFields[k] = string(v)
	}
	rawJSON, err := json.Marshal(jsonFields)
	if err != nil {
		return fmt.Errorf("marshal fields: %w", err)
	}

	var expiresAt interface{}
	if !op.expiresAt.IsZero() {
		expiresAt = op.expiresAt.UTC()
	}
	_, err = d.pool.ExecContext(ctx, `
        INSERT INTO session_hashes (key, fields, expires_at)
        VALUES ($1, $2::jsonb, $3)
        ON CONFLICT (key) DO UPDATE
            SET fields     = session_hashes.fields || EXCLUDED.fields,
                expires_at = COALESCE(session_hashes.expires_at, EXCLUDED.expires_at)
    `, op.key, rawJSON, expiresAt)
	return err
}

func (d *DB) execDeleteKeys(ctx context.Context, keys []string) error {
	placeholders := make([]string, len(keys))
	args := make([]any, len(keys))
	for i, k := range keys {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = k
	}
	in := strings.Join(placeholders, ",")
	if _, err := d.pool.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM sessions WHERE key IN (%s)", in), args...); err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}
	if _, err := d.pool.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM session_hashes WHERE key IN (%s)", in), args...); err != nil {
		return fmt.Errorf("delete session_hashes: %w", err)
	}
	return nil
}

func (d *DB) LoadAll(
	sessionFn func(key string, value []byte, expiresAt time.Time),
	hashFn func(key string, fields map[string][]byte, expiresAt time.Time),
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rows, err := d.pool.QueryContext(ctx,
		`SELECT key, value, expires_at FROM sessions
         WHERE expires_at IS NULL OR expires_at > NOW()`)
	if err != nil {
		return fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var value []byte
		var expiresAt sql.NullTime
		if err := rows.Scan(&key, &value, &expiresAt); err != nil {
			return fmt.Errorf("scan session row: %w", err)
		}
		var t time.Time
		if expiresAt.Valid {
			t = expiresAt.Time
		}
		sessionFn(key, value, t)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sessions: %w", err)
	}

	hrows, err := d.pool.QueryContext(ctx,
		`SELECT key, fields, expires_at FROM session_hashes
         WHERE expires_at IS NULL OR expires_at > NOW()`)
	if err != nil {
		return fmt.Errorf("query session_hashes: %w", err)
	}
	defer hrows.Close()
	for hrows.Next() {
		var key string
		var rawJSON []byte
		var expiresAt sql.NullTime
		if err := hrows.Scan(&key, &rawJSON, &expiresAt); err != nil {
			return fmt.Errorf("scan hash row: %w", err)
		}
		var jsonFields map[string]string
		if err := json.Unmarshal(rawJSON, &jsonFields); err != nil {
			return fmt.Errorf("unmarshal fields for key %q: %w", key, err)
		}
		fields := make(map[string][]byte, len(jsonFields))
		for k, v := range jsonFields {
			fields[k] = []byte(v)
		}
		var t time.Time
		if expiresAt.Valid {
			t = expiresAt.Time
		}
		hashFn(key, fields, t)
	}
	return hrows.Err()
}

func (d *DB) FlushAll(ctx context.Context) error {
	_, err := d.pool.ExecContext(ctx, `TRUNCATE sessions, session_hashes`)
	return err
}

func (d *DB) Close() {
	close(d.done)
	<-d.closed
	d.pool.Close()
}
