package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the CLI's persisted state: the cloud session, the default printer
// and LAN printers. It lives in $XDG_CONFIG_HOME/bambu/config.json (0600).
type Config struct {
	Region       string       `json:"region,omitempty"`
	Account      string       `json:"account,omitempty"`
	Token        string       `json:"token,omitempty"`
	RefreshToken string       `json:"refreshToken,omitempty"`
	HardwareID   string       `json:"hardwareId,omitempty"` // stable fake phone id (X-BBL-Device-ID, MQTT client id)
	Printer      string       `json:"printer,omitempty"`    // default serial
	Server       string       `json:"server,omitempty"`     // remote bambu-api base URL; empty = in-process
	APIKey       string       `json:"apiKey,omitempty"`
	LAN          []LANPrinter `json:"lan,omitempty"`

	path string
}

// LANPrinter is a printer reachable directly over the local network.
type LANPrinter struct {
	Serial     string `json:"serial"`
	IP         string `json:"ip"`
	AccessCode string `json:"accessCode"`
	Name       string `json:"name,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
}

func configPath() (string, error) {
	if p := os.Getenv("BAMBU_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "bambu", "config.json"), nil
}

func loadConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	cfg := &Config{path: p}
	data, err := os.ReadFile(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if cfg.Region == "" {
		cfg.Region = "intl"
	}
	if cfg.HardwareID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		cfg.HardwareID = "bambu-cli-" + hex.EncodeToString(b)
	}
	return cfg, nil
}

func (c *Config) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func (c *Config) lanPrinter(serial string) *LANPrinter {
	for i := range c.LAN {
		if c.LAN[i].Serial == serial {
			return &c.LAN[i]
		}
	}
	return nil
}
