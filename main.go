package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yourorg/go-session-server/internal/auth"
	"github.com/yourorg/go-session-server/internal/config"
	"github.com/yourorg/go-session-server/internal/resp"
	"github.com/yourorg/go-session-server/internal/store"
	tlsutil "github.com/yourorg/go-session-server/internal/tls"
)

// ─── Server ───────────────────────────────────────────────────────────────────

type Server struct {
	cfg         *config.Config
	store       *store.Store
	auth        *auth.Manager
	listener    net.Listener
	activeConns atomic.Int64
	mu          sync.Mutex
}

func NewServer(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
		store: store.New(
			cfg.Server.ShardCount,
			cfg.Session.DefaultTTL,
			cfg.Session.MaxTTL,
			cfg.Session.SweepInterval,
			cfg.Session.MaxKeys,
		),
		auth: auth.New(cfg.Auth.Password, cfg.Auth.RequireAuth, cfg.Auth.AllowedIPs),
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)

	var (
		ln  net.Listener
		err error
	)

	if s.cfg.TLS.Enabled {
		tlsCfg, tlsErr := tlsutil.LoadOrGenerate(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if tlsErr != nil {
			return fmt.Errorf("TLS setup: %w", tlsErr)
		}
		ln, err = tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS listen on %s: %w", addr, err)
		}
		log.Printf("[server] Listening on %s (TLS ✓)", addr)
	} else {
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", addr, err)
		}
		log.Printf("[server] Listening on %s (TLS disabled)", addr)
	}

	log.Printf("[server] Auth required: %v", s.cfg.Auth.RequireAuth)
	log.Printf("[server] IP allowlist:  %s", s.auth.AllowlistSummary())
	log.Printf("[server] Session TTL — default: %s | max: %s | sweep: %s",
		s.cfg.Session.DefaultTTL,
		s.cfg.Session.MaxTTL,
		s.cfg.Session.SweepInterval,
	)

	s.listener = ln

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // server closed
		}

		// ── IP Allowlist check (first gate) ───────────────────
		if !s.auth.IsIPAllowed(conn.RemoteAddr().String()) {
			log.Printf("[security] DENIED connection from %s — not in IP allowlist", conn.RemoteAddr())
			conn.Close()
			continue
		}

		// ── Max connections check ──────────────────────────────
		if s.cfg.Server.MaxConnections > 0 &&
			s.activeConns.Load() >= int64(s.cfg.Server.MaxConnections) {
			log.Printf("[server] Max connections (%d) reached — refusing %s",
				s.cfg.Server.MaxConnections, conn.RemoteAddr())
			conn.Close()
			continue
		}

		s.activeConns.Add(1)
		go s.handleConn(conn)
	}
}

func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.store.Close()
}

// ─── Connection Handler ───────────────────────────────────────────────────────

type connState struct {
	conn          net.Conn
	authenticated bool
	parser        *resp.Parser
	writer        *resp.Writer
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		s.activeConns.Add(-1)
	}()

	if s.cfg.Logging.Level == "debug" {
		log.Printf("[conn] New connection from %s", conn.RemoteAddr())
	}

	state := &connState{
		conn:          conn,
		authenticated: !s.auth.RequiresAuth(),
		parser:        resp.NewParser(conn),
		writer:        resp.NewWriter(conn),
	}

	for {
		if s.cfg.Server.ReadTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(s.cfg.Server.ReadTimeout))
		}
		cmd, err := state.parser.ReadCommand()
		if err != nil {
			return
		}
		if s.cfg.Server.WriteTimeout > 0 {
			conn.SetWriteDeadline(time.Now().Add(s.cfg.Server.WriteTimeout))
		}
		s.dispatch(state, cmd)
	}
}

// ─── Command Dispatcher ───────────────────────────────────────────────────────

func (s *Server) dispatch(c *connState, cmd *resp.Command) {
	switch cmd.Name {
	case "AUTH":
		s.cmdAuth(c, cmd)
		return
	case "QUIT":
		c.writer.WriteOK()
		c.conn.Close()
		return
	case "PING":
		if !c.authenticated {
			c.writer.WriteError("NOAUTH Authentication required")
			return
		}
		if len(cmd.Args) > 0 {
			c.writer.WriteBulkString(cmd.Args[0])
		} else {
			c.writer.WriteSimpleString("PONG")
		}
		return
	}

	if !c.authenticated {
		c.writer.WriteError("NOAUTH Authentication required. Use AUTH <password>")
		return
	}

	switch cmd.Name {
	case "SET":
		s.cmdSet(c, cmd)
	case "GET":
		s.cmdGet(c, cmd)
	case "DEL":
		s.cmdDel(c, cmd)
	case "EXISTS":
		s.cmdExists(c, cmd)
	case "EXPIRE":
		s.cmdExpire(c, cmd)
	case "EXPIREAT":
		s.cmdExpireAt(c, cmd)
	case "PEXPIRE":
		s.cmdPExpire(c, cmd)
	case "TTL":
		s.cmdTTL(c, cmd)
	case "PTTL":
		s.cmdPTTL(c, cmd)
	case "SETNX":
		s.cmdSetNX(c, cmd)
	case "SETEX":
		s.cmdSetEX(c, cmd)
	case "GETSET":
		s.cmdGetSet(c, cmd)
	case "GETDEL":
		s.cmdGetDel(c, cmd)
	case "FLUSHALL", "FLUSHDB":
		s.store.FlushAll()
		c.writer.WriteOK()
	case "DBSIZE":
		c.writer.WriteInteger(s.store.Len())
	case "INFO":
		s.cmdInfo(c, cmd)
	case "CONFIG":
		s.cmdConfig(c, cmd)
	case "SELECT":
		c.writer.WriteOK() // single DB
	case "COMMAND":
		c.writer.WriteSimpleString("OK")
	case "RESET":
		c.writer.WriteSimpleString("RESET")
	case "CLIENT":
		s.cmdClient(c, cmd)
	default:
		c.writer.WriteError(fmt.Sprintf("ERR unknown command '%s'", cmd.Name))
	}
}

// ─── AUTH ────────────────────────────────────────────────────────────────────

func (s *Server) cmdAuth(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'AUTH'")
		return
	}
	if s.auth.CheckPassword(string(cmd.Args[0])) {
		c.authenticated = true
		c.writer.WriteOK()
	} else {
		c.authenticated = false
		log.Printf("[security] Failed AUTH attempt from %s", c.conn.RemoteAddr())
		c.writer.WriteError("WRONGPASS invalid username-password pair")
	}
}

// ─── SET key value [EX seconds] [PX ms] [NX] [XX] ────────────────────────────

func (s *Server) cmdSet(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 2 {
		c.writer.WriteError("wrong number of arguments for 'SET'")
		return
	}
	key := string(cmd.Args[0])
	value := cmd.Args[1]

	var ttl time.Duration
	nx, xx := false, false

	for i := 2; i < len(cmd.Args); i++ {
		opt := strings.ToUpper(string(cmd.Args[i]))
		switch opt {
		case "EX":
			if i+1 >= len(cmd.Args) {
				c.writer.WriteError("syntax error")
				return
			}
			i++
			secs, err := strconv.ParseInt(string(cmd.Args[i]), 10, 64)
			if err != nil || secs <= 0 {
				c.writer.WriteError("invalid expire time in 'SET'")
				return
			}
			ttl = time.Duration(secs) * time.Second
		case "PX":
			if i+1 >= len(cmd.Args) {
				c.writer.WriteError("syntax error")
				return
			}
			i++
			ms, err := strconv.ParseInt(string(cmd.Args[i]), 10, 64)
			if err != nil || ms <= 0 {
				c.writer.WriteError("invalid expire time in 'SET'")
				return
			}
			ttl = time.Duration(ms) * time.Millisecond
		case "NX":
			nx = true
		case "XX":
			xx = true
		case "KEEPTTL":
			ttl = -1
		}
	}

	if nx {
		if s.store.SetNX(key, value, ttl) {
			c.writer.WriteOK()
		} else {
			c.writer.WriteNull()
		}
		return
	}
	if xx && s.store.Exists(key) == 0 {
		c.writer.WriteNull()
		return
	}
	if !s.store.Set(key, value, ttl) {
		c.writer.WriteError("ERR store is full (max_keys reached)")
		return
	}
	c.writer.WriteOK()
}

func (s *Server) cmdGet(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'GET'")
		return
	}
	c.writer.WriteBulkString(s.store.Get(string(cmd.Args[0])))
}

func (s *Server) cmdDel(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'DEL'")
		return
	}
	keys := make([]string, len(cmd.Args))
	for i, a := range cmd.Args {
		keys[i] = string(a)
	}
	c.writer.WriteInteger(int64(s.store.Delete(keys...)))
}

func (s *Server) cmdExists(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'EXISTS'")
		return
	}
	keys := make([]string, len(cmd.Args))
	for i, a := range cmd.Args {
		keys[i] = string(a)
	}
	c.writer.WriteInteger(int64(s.store.Exists(keys...)))
}

func (s *Server) cmdExpire(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 2 {
		c.writer.WriteError("wrong number of arguments for 'EXPIRE'")
		return
	}
	secs, err := strconv.ParseInt(string(cmd.Args[1]), 10, 64)
	if err != nil {
		c.writer.WriteError("value is not an integer")
		return
	}
	if s.store.Expire(string(cmd.Args[0]), time.Duration(secs)*time.Second) {
		c.writer.WriteInteger(1)
	} else {
		c.writer.WriteInteger(0)
	}
}

func (s *Server) cmdExpireAt(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 2 {
		c.writer.WriteError("wrong number of arguments for 'EXPIREAT'")
		return
	}
	ts, err := strconv.ParseInt(string(cmd.Args[1]), 10, 64)
	if err != nil {
		c.writer.WriteError("value is not an integer")
		return
	}
	ttl := time.Until(time.Unix(ts, 0))
	if ttl <= 0 {
		s.store.Delete(string(cmd.Args[0]))
		c.writer.WriteInteger(1)
		return
	}
	if s.store.Expire(string(cmd.Args[0]), ttl) {
		c.writer.WriteInteger(1)
	} else {
		c.writer.WriteInteger(0)
	}
}

func (s *Server) cmdPExpire(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 2 {
		c.writer.WriteError("wrong number of arguments for 'PEXPIRE'")
		return
	}
	ms, err := strconv.ParseInt(string(cmd.Args[1]), 10, 64)
	if err != nil {
		c.writer.WriteError("value is not an integer")
		return
	}
	if s.store.Expire(string(cmd.Args[0]), time.Duration(ms)*time.Millisecond) {
		c.writer.WriteInteger(1)
	} else {
		c.writer.WriteInteger(0)
	}
}

func (s *Server) cmdTTL(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'TTL'")
		return
	}
	ttl := s.store.TTL(string(cmd.Args[0]))
	switch ttl {
	case -2:
		c.writer.WriteInteger(-2)
	case -1:
		c.writer.WriteInteger(-1)
	default:
		c.writer.WriteInteger(int64(ttl.Seconds()))
	}
}

func (s *Server) cmdPTTL(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'PTTL'")
		return
	}
	ttl := s.store.TTL(string(cmd.Args[0]))
	switch ttl {
	case -2:
		c.writer.WriteInteger(-2)
	case -1:
		c.writer.WriteInteger(-1)
	default:
		c.writer.WriteInteger(int64(ttl.Milliseconds()))
	}
}

func (s *Server) cmdSetNX(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 2 {
		c.writer.WriteError("wrong number of arguments for 'SETNX'")
		return
	}
	if s.store.SetNX(string(cmd.Args[0]), cmd.Args[1], 0) {
		c.writer.WriteInteger(1)
	} else {
		c.writer.WriteInteger(0)
	}
}

func (s *Server) cmdSetEX(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 3 {
		c.writer.WriteError("wrong number of arguments for 'SETEX'")
		return
	}
	secs, err := strconv.ParseInt(string(cmd.Args[1]), 10, 64)
	if err != nil || secs <= 0 {
		c.writer.WriteError("invalid expire time in 'SETEX'")
		return
	}
	s.store.Set(string(cmd.Args[0]), cmd.Args[2], time.Duration(secs)*time.Second)
	c.writer.WriteOK()
}

func (s *Server) cmdGetSet(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 2 {
		c.writer.WriteError("wrong number of arguments for 'GETSET'")
		return
	}
	old := s.store.Get(string(cmd.Args[0]))
	s.store.Set(string(cmd.Args[0]), cmd.Args[1], 0)
	c.writer.WriteBulkString(old)
}

func (s *Server) cmdGetDel(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'GETDEL'")
		return
	}
	val := s.store.Get(string(cmd.Args[0]))
	if val != nil {
		s.store.Delete(string(cmd.Args[0]))
	}
	c.writer.WriteBulkString(val)
}

func (s *Server) cmdInfo(c *connState, _ *resp.Command) {
	hits, misses, sets, dels := s.store.Stats()
	info := fmt.Sprintf(
		"# Server\r\ngo_session_server_version:1.0.0\r\n"+
			"\r\n# Clients\r\nconnected_clients:%d\r\n"+
			"\r\n# Stats\r\n"+
			"total_keys:%d\r\n"+
			"keyspace_hits:%d\r\nkeyspace_misses:%d\r\n"+
			"total_sets:%d\r\ntotal_dels:%d\r\n"+
			"\r\n# Config\r\n"+
			"default_ttl_seconds:%d\r\nmax_ttl_seconds:%d\r\nshard_count:%d\r\n"+
			"ip_allowlist:%s\r\n"+
			"tls_enabled:%v\r\nauth_required:%v\r\n",
		s.activeConns.Load(),
		s.store.Len(),
		hits, misses, sets, dels,
		int64(s.cfg.Session.DefaultTTL.Seconds()),
		int64(s.cfg.Session.MaxTTL.Seconds()),
		s.cfg.Server.ShardCount,
		s.auth.AllowlistSummary(),
		s.cfg.TLS.Enabled,
		s.cfg.Auth.RequireAuth,
	)
	c.writer.WriteBulkString([]byte(info))
}

func (s *Server) cmdConfig(c *connState, cmd *resp.Command) {
	if len(cmd.Args) < 1 {
		c.writer.WriteError("wrong number of arguments for 'CONFIG'")
		return
	}
	switch strings.ToUpper(string(cmd.Args[0])) {
	case "GET":
		c.writer.WriteArray([][]byte{})
	case "SET", "RESETSTAT":
		c.writer.WriteOK()
	default:
		c.writer.WriteOK()
	}
}

func (s *Server) cmdClient(c *connState, cmd *resp.Command) {
	if len(cmd.Args) == 0 {
		c.writer.WriteOK()
		return
	}
	switch strings.ToUpper(string(cmd.Args[0])) {
	case "SETNAME":
		c.writer.WriteOK()
	case "GETNAME":
		c.writer.WriteBulkString([]byte("go-session-server"))
	case "ID":
		c.writer.WriteInteger(1)
	case "INFO":
		c.writer.WriteBulkString([]byte("id=1 addr=127.0.0.1:0 name=go-session-server"))
	default:
		c.writer.WriteOK()
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	cfgPath := "config.conf"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("[startup] Failed to load config: %v", err)
	}

	srv := NewServer(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[server] Received %s — shutting down gracefully...", sig)
		srv.Stop()
		os.Exit(0)
	}()

	if err := srv.Start(); err != nil {
		log.Fatalf("[server] Fatal: %v", err)
	}
}
