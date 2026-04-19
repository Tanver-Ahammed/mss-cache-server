package db

import (
	"context"
	"database/sql"
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
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'session_hashes' AND column_name = 'fields'
    ) THEN
        DROP TABLE session_hashes CASCADE;
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS sessions (
    key        TEXT        NOT NULL PRIMARY KEY,
    value      BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS session_hashes (
    key        TEXT        NOT NULL PRIMARY KEY,
    expires_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS session_hash_fields (
    key   TEXT  NOT NULL REFERENCES session_hashes(key) ON DELETE CASCADE,
    field TEXT  NOT NULL,
    value BYTEA NOT NULL,
    PRIMARY KEY (key, field)
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
	var expiresAt interface{}
	if !op.expiresAt.IsZero() {
		expiresAt = op.expiresAt.UTC()
	}

	tx, err := d.pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO session_hashes (key, expires_at)
        VALUES ($1, $2)
        ON CONFLICT (key) DO UPDATE
            SET expires_at = COALESCE(session_hashes.expires_at, EXCLUDED.expires_at)
    `, op.key, expiresAt); err != nil {
		return fmt.Errorf("upsert session_hashes: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO session_hash_fields (key, field, value)
        VALUES ($1, $2, $3)
        ON CONFLICT (key, field) DO UPDATE SET value = EXCLUDED.value
    `)
	if err != nil {
		return fmt.Errorf("prepare field upsert: %w", err)
	}
	defer stmt.Close()

	for field, value := range op.fields {
		if _, err := stmt.ExecContext(ctx, op.key, field, value); err != nil {
			return fmt.Errorf("upsert field %q: %w", field, err)
		}
	}

	return tx.Commit()
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

	hrows, err := d.pool.QueryContext(ctx, `
        SELECT h.key, h.expires_at, f.field, f.value
        FROM session_hashes h
        LEFT JOIN session_hash_fields f ON f.key = h.key
        WHERE h.expires_at IS NULL OR h.expires_at > NOW()
        ORDER BY h.key`)
	if err != nil {
		return fmt.Errorf("query session_hashes: %w", err)
	}
	defer hrows.Close()

	var (
		haveKey      bool
		curKey       string
		curFields    map[string][]byte
		curExpiresAt time.Time
	)
	flush := func() {
		if haveKey {
			hashFn(curKey, curFields, curExpiresAt)
		}
	}
	for hrows.Next() {
		var key string
		var expiresAt sql.NullTime
		var field sql.NullString
		var value []byte
		if err := hrows.Scan(&key, &expiresAt, &field, &value); err != nil {
			return fmt.Errorf("scan hash row: %w", err)
		}
		if !haveKey || key != curKey {
			flush()
			haveKey = true
			curKey = key
			curFields = make(map[string][]byte)
			if expiresAt.Valid {
				curExpiresAt = expiresAt.Time
			} else {
				curExpiresAt = time.Time{}
			}
		}
		if field.Valid {
			curFields[field.String] = value
		}
	}
	if err := hrows.Err(); err != nil {
		return err
	}
	flush()
	return nil
}

func (d *DB) FlushAll(ctx context.Context) error {
	_, err := d.pool.ExecContext(ctx, `TRUNCATE sessions, session_hash_fields, session_hashes`)
	return err
}

func (d *DB) Close() {
	close(d.done)
	<-d.closed
	d.pool.Close()
}
