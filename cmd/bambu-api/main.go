// Command bambu-api exposes everything the Bambu Handy app can do as a plain
// HTTP/JSON API: cloud login, the full cloud REST surface (396 endpoints), and
// printer control over MQTT (90 commands, live state, event stream) in cloud or
// LAN mode.
package main

import (
	"context"
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
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

func main() {
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
	srv := api.New(api.Config{
		Region:        reg,
		APIKey:        *apiKey,
		HardwareID:    *hardwareID,
		AppCert:       appCert,
		IdleAfter:     *idle,
		LANExtraRoots: extraRoots,
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
	log.Printf("bambu-api listening on %s (region %s, %d cloud endpoints, %d printer commands)", *addr, reg.Name, len(cloud.Endpoints), srv.CommandCount())
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
