// Command bambu-api exposes everything the Bambu Handy app can do as a plain
// HTTP/JSON API: cloud login, the full cloud REST surface (396 endpoints), and
// printer control over MQTT (90 commands, live state, event stream) in cloud or
// LAN mode.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lordbagel42/bambu-rea/internal/api"
	"github.com/lordbagel42/bambu-rea/internal/store"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

// version is stamped by the Docker build (-ldflags -X main.version=...).
var version = "dev"

func main() {
	// Secrets can come from a file the deployment mounts read-only (as the
	// homelab Nomad job does) instead of the process environment, which the
	// scheduler's UI would show.
	if f := os.Getenv("BAMBU_ENV_FILE"); f != "" {
		if err := loadEnvFile(f); err != nil {
			log.Fatal(err)
		}
	}
	var (
		addr       = flag.String("addr", envOr("BAMBU_API_ADDR", ":8080"), "listen address")
		region     = flag.String("region", envOr("BAMBU_REGION", "intl"), "cloud region: intl|china")
		apiKey     = flag.String("api-key", os.Getenv("BAMBU_API_KEY"), "if set, every request must carry X-API-Key")
		hardwareID = flag.String("hardware-id", envOr("BAMBU_HARDWARE_ID", "bambu-rea"), "stable id used in the MQTT client id and X-BBL-Device-ID")
		certFile   = flag.String("app-cert", os.Getenv("BAMBU_APP_CERT"), "optional PEM file with a captured IoT app certificate")
		keyFile    = flag.String("app-key", os.Getenv("BAMBU_APP_KEY"), "optional PEM file with the app certificate private key")
		crlFile    = flag.String("app-crl", os.Getenv("BAMBU_APP_CRL"), "optional PEM file with the app certificate CRL (sent to printers on app_cert_install)")
		idle       = flag.Duration("mqtt-idle", 15*time.Minute, "close MQTT sessions idle for this long")
		lanCA      = flag.String("lan-ca", os.Getenv("BAMBU_LAN_CA"), "optional extra PEM CA bundle trusted for LAN printers")
		dbPath     = flag.String("db", os.Getenv("BAMBU_DB"), "SQLite file for accounts and API keys; enables /login, /v1/keys and /mcp")
		dataKey    = flag.String("data-key", os.Getenv("BAMBU_DATA_KEY"), "64 hex chars (32 bytes) used to encrypt stored Bambu tokens; strongly recommended with -db")
		publicURL  = flag.String("public-url", os.Getenv("BAMBU_PUBLIC_URL"), "externally visible base URL, e.g. https://bambuapi.example.com")
		cors       = flag.String("cors-origins", os.Getenv("BAMBU_CORS_ORIGINS"), "comma-separated browser origins allowed to call the API (\"*\" for any)")
	)
	flag.Parse()

	reg, ok := cloud.RegionByName(*region)
	if !ok {
		log.Fatalf("unknown region %q", *region)
	}
	var appCert *cloud.AppCert
	if *certFile != "" || *keyFile != "" {
		if *certFile == "" || *keyFile == "" {
			log.Fatal("-app-cert and -app-key must be given together")
		}
		certPEM, err := os.ReadFile(*certFile)
		if err != nil {
			log.Fatal(err)
		}
		keyPEM, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		var crlPEM []byte
		if *crlFile != "" {
			if crlPEM, err = os.ReadFile(*crlFile); err != nil {
				log.Fatal(err)
			}
		}
		appCert, err = cloud.ParseAppCert(string(certPEM), string(keyPEM), string(crlPEM))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("using supplied app certificate %s", appCert.CertID)
	}

	var extraRoots [][]byte
	if *lanCA != "" {
		pemBytes, err := os.ReadFile(*lanCA)
		if err != nil {
			log.Fatal(err)
		}
		extraRoots = append(extraRoots, pemBytes)
	}
	var st *store.Store
	if *dbPath != "" {
		var key []byte
		if *dataKey != "" {
			k, err := hex.DecodeString(strings.TrimSpace(*dataKey))
			if err != nil || len(k) != 32 {
				log.Fatal("-data-key must be 64 hex characters (32 bytes)")
			}
			key = k
		} else {
			log.Print("warning: -db without -data-key stores Bambu tokens unencrypted")
		}
		var err error
		if st, err = store.Open(*dbPath, key); err != nil {
			log.Fatal(err)
		}
		defer st.Close()
	}
	var origins []string
	for _, o := range strings.Split(*cors, ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	srv := api.New(api.Config{
		Region:        reg,
		APIKey:        *apiKey,
		HardwareID:    *hardwareID,
		AppCert:       appCert,
		IdleAfter:     *idle,
		LANExtraRoots: extraRoots,
		Store:         st,
		PublicURL:     strings.TrimRight(*publicURL, "/"),
		CORSOrigins:   origins,
	})
	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
		srv.Close()
	}()
	log.Printf("bambu-api %s listening on %s (region %s, %d cloud endpoints, %d printer commands, accounts %s)", version, *addr, reg.Name, len(cloud.Endpoints), srv.CommandCount(), map[bool]string{true: "persisted in " + *dbPath, false: "not persisted"}[st != nil])
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// loadEnvFile sets KEY=VALUE lines from a dotenv-style file into the process
// environment without overriding variables that are already set.
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s: malformed line %q", path, line)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			if err := os.Setenv(k, v); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
