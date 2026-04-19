package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Server   ServerConfig
	Auth     AuthConfig
	TLS      TLSConfig
	Session  SessionConfig
	Logging  LoggingConfig
	Database DatabaseConfig
}

type ServerConfig struct {
	Host           string
	Port           int
	MaxConnections int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	ShardCount     int
}

type AuthConfig struct {
	Password    string
	AllowedIPs  []string // CIDR or plain IPs: "192.168.1.0/24", "10.0.0.5"
	RequireAuth bool
}

type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

type SessionConfig struct {
	DefaultTTL    time.Duration
	MaxTTL        time.Duration
	SweepInterval time.Duration
	MaxKeys       int
}

type LoggingConfig struct {
	Level  string
	Format string
}

type DatabaseConfig struct {
	Enabled    bool
	DSN        string
	Host       string
	Port       int
	Name       string
	User       string
	Password   string
	SSLMode    string
	QueueDepth int
}

// DSNString returns the effective DSN. If the DSN field is set it is returned
// as-is; otherwise it is built from Host/Port/Name/User/Password/SSLMode.
func (d DatabaseConfig) DSNString() string {
	if d.DSN != "" {
		return d.DSN
	}
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode,
	)
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           6379,
			MaxConnections: 1000,
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			ShardCount:     256,
		},
		Auth: AuthConfig{
			RequireAuth: true,
			Password:    "change-me-strong-password",
		},
		TLS: TLSConfig{
			Enabled:  false,
			CertFile: "certs/server.crt",
			KeyFile:  "certs/server.key",
		},
		Session: SessionConfig{
			DefaultTTL:    30 * time.Minute,
			MaxTTL:        24 * time.Hour,
			SweepInterval: 1 * time.Minute,
			MaxKeys:       0,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Database: DatabaseConfig{
			Enabled:    false,
			Host:       "localhost",
			Port:       5432,
			Name:       "sessions",
			User:       "postgres",
			Password:   "",
			SSLMode:    "disable",
			QueueDepth: 4096,
		},
	}
}

// Load reads KEY=VALUE config file then overlays environment variables.
// Zero external dependencies — pure stdlib only.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("[config] %s not found, using defaults\n", path)
			return applyEnv(cfg), nil
		}
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		applyKey(cfg, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	return applyEnv(cfg), nil
}

func applyKey(cfg *Config, key, val string) {
	switch key {
	case "SERVER_HOST":
		cfg.Server.Host = val
	case "SERVER_PORT":
		if n, err := strconv.Atoi(val); err == nil {
			cfg.Server.Port = n
		}
	case "SERVER_MAX_CONNECTIONS":
		if n, err := strconv.Atoi(val); err == nil {
			cfg.Server.MaxConnections = n
		}
	case "SERVER_READ_TIMEOUT":
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Server.ReadTimeout = d
		}
	case "SERVER_WRITE_TIMEOUT":
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Server.WriteTimeout = d
		}
	case "SERVER_SHARD_COUNT":
		if n, err := strconv.Atoi(val); err == nil {
			cfg.Server.ShardCount = n
		}
	case "AUTH_PASSWORD":
		cfg.Auth.Password = val
	case "AUTH_REQUIRE":
		cfg.Auth.RequireAuth = val == "true" || val == "1"
	case "AUTH_ALLOWED_IPS":
		// Comma-separated: "192.168.1.10, 10.0.0.0/24"
		if val != "" {
			parts := strings.Split(val, ",")
			cfg.Auth.AllowedIPs = make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					cfg.Auth.AllowedIPs = append(cfg.Auth.AllowedIPs, p)
				}
			}
		}
	case "TLS_ENABLED":
		cfg.TLS.Enabled = val == "true" || val == "1"
	case "TLS_CERT_FILE":
		cfg.TLS.CertFile = val
	case "TLS_KEY_FILE":
		cfg.TLS.KeyFile = val
	case "SESSION_DEFAULT_TTL":
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Session.DefaultTTL = d
		}
	case "SESSION_MAX_TTL":
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Session.MaxTTL = d
		}
	case "SESSION_SWEEP_INTERVAL":
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Session.SweepInterval = d
		}
	case "SESSION_MAX_KEYS":
		if n, err := strconv.Atoi(val); err == nil {
			cfg.Session.MaxKeys = n
		}
	case "LOG_LEVEL":
		cfg.Logging.Level = val
	case "LOG_FORMAT":
		cfg.Logging.Format = val
	case "DB_ENABLED":
		cfg.Database.Enabled = val == "true" || val == "1"
	case "DB_DSN":
		cfg.Database.DSN = val
	case "DB_HOST":
		cfg.Database.Host = val
	case "DB_PORT":
		if n, err := strconv.Atoi(val); err == nil {
			cfg.Database.Port = n
		}
	case "MSS_DB_NAME":
		cfg.Database.Name = val
	case "MSS_DB_USER":
		cfg.Database.User = val
	case "MSS_DB_PASSWORD":
		cfg.Database.Password = val
	case "DB_SSLMODE":
		cfg.Database.SSLMode = val
	case "DB_QUEUE_DEPTH":
		if n, err := strconv.Atoi(val); err == nil {
			cfg.Database.QueueDepth = n
		}
	}
}

func applyEnv(cfg *Config) *Config {
	keys := []string{
		"SERVER_HOST", "SERVER_PORT", "SERVER_MAX_CONNECTIONS",
		"SERVER_READ_TIMEOUT", "SERVER_WRITE_TIMEOUT", "SERVER_SHARD_COUNT",
		"AUTH_PASSWORD", "AUTH_REQUIRE", "AUTH_ALLOWED_IPS",
		"TLS_ENABLED", "TLS_CERT_FILE", "TLS_KEY_FILE",
		"SESSION_DEFAULT_TTL", "SESSION_MAX_TTL", "SESSION_SWEEP_INTERVAL", "SESSION_MAX_KEYS",
		"LOG_LEVEL", "LOG_FORMAT",
		"DB_ENABLED", "DB_DSN", "DB_HOST", "DB_PORT", "MSS_DB_NAME",
		"MSS_DB_USER", "MSS_DB_PASSWORD", "DB_SSLMODE", "DB_QUEUE_DEPTH",
	}
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			applyKey(cfg, k, v)
		}
	}
	return cfg
}
