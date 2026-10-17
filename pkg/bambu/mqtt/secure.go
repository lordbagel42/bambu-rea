package mqtt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/secure"
)

// SecureChannel reproduces the app's "secure command" mode (defpackage/im5):
// the whole envelope is signed with the app certificate's RSA key and sensitive
// fields (print:param, print:url, liveview:ttcode) are RSA-encrypted with the
// printer's certificate obtained via security/app_cert_install.
//
// It is optional: printers accept unsigned plaintext commands from a client
// that has not installed an app certificate, which is also what every
// third-party integration does today.
type SecureChannel struct {
	// Key is the RSA private key of the app certificate (from cloud.AppCert).
	Key *rsa.PrivateKey
	// CertID is the certificate id the printer reports in security.cert_ids.
	CertID string
	// PrinterCert is the printer's RSA public key (security.printer_cert); nil
	// disables field encryption but keeps signing.
	PrinterCert *rsa.PublicKey
	// PrinterCertPEM is the raw printer_cert string, kept for status reporting.
	PrinterCertPEM string
}

// Sign returns the serialized envelope with a trailing "header" object, exactly
// as hhp.java emits it: canonical (sorted, compact) body first, then
// `"header":{...}` appended inside the closing brace.
func (s *SecureChannel) Sign(envelope map[string]any) ([]byte, error) {
	if s == nil || s.Key == nil {
		return nil, errors.New("mqtt: secure channel has no app key")
	}
	if s.CertID == "" {
		return nil, errors.New("mqtt: secure channel has no cert id")
	}
	body, err := secure.CanonicalJSON(envelope)
	if err != nil {
		return nil, err
	}
	sig, err := secure.SignSHA256(s.Key, body)
	if err != nil {
		return nil, err
	}
	header := map[string]any{
		"sign_ver":    "v1.0",
		"sign_alg":    "RSA_SHA256",
		"sign_string": base64.StdEncoding.EncodeToString(sig),
		"cert_id":     s.CertID,
		"payload_len": len(body),
	}
	hb, err := secure.CanonicalJSON(header)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(string(body), "}") {
		return nil, fmt.Errorf("mqtt: unexpected canonical body %q", body)
	}
	trimmed := body[:len(body)-1]
	var out strings.Builder
	out.Grow(len(body) + len(hb) + 16)
	out.Write(trimmed)
	if len(trimmed) > 1 {
		out.WriteString(",")
	}
	out.WriteString(`"header":`)
	out.Write(hb)
	out.WriteString("}")
	return []byte(out.String()), nil
}

// EncryptFields replaces each "module:field" path in envelope with
// "<field>_enc" = base64(RSA-PKCS1v15(printerCert, value)). Missing paths are
// ignored, as in the app.
func (s *SecureChannel) EncryptFields(envelope map[string]any, paths []string) error {
	if s == nil || s.PrinterCert == nil || len(paths) == 0 {
		return nil
	}
	for _, p := range paths {
		parts := strings.Split(p, ":")
		if len(parts) < 2 {
			return fmt.Errorf("mqtt: invalid encrypt field path %q", p)
		}
		obj := envelope
		ok := true
		for _, k := range parts[:len(parts)-1] {
			next, isMap := obj[k].(map[string]any)
			if !isMap {
				ok = false
				break
			}
			obj = next
		}
		if !ok {
			continue
		}
		field := parts[len(parts)-1]
		v, present := obj[field]
		if !present || v == nil {
			continue
		}
		var plain string
		if str, isStr := v.(string); isStr {
			plain = str
		} else {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			plain = string(b)
		}
		ct, err := secure.EncryptPKCS1v15(s.PrinterCert, []byte(plain))
		if err != nil {
			return fmt.Errorf("mqtt: RSA encrypt failed for field %q: %w", field, err)
		}
		delete(obj, field)
		obj[field+"_enc"] = base64.StdEncoding.EncodeToString(ct)
	}
	return nil
}

// ParseCertIDs extracts security.cert_ids from a report payload (app_cert_list reply).
func ParseCertIDs(report []byte) []string {
	var r struct {
		Security struct {
			CertIDs []string `json:"cert_ids"`
		} `json:"security"`
	}
	if json.Unmarshal(report, &r) != nil {
		return nil
	}
	return r.Security.CertIDs
}

// ParsePrinterCert extracts security.printer_cert from a report payload
// (app_cert_install reply) and parses it as an RSA public key / certificate.
func ParsePrinterCert(report []byte) (*rsa.PublicKey, string, error) {
	var r struct {
		Security struct {
			PrinterCert string `json:"printer_cert"`
		} `json:"security"`
	}
	if err := json.Unmarshal(report, &r); err != nil {
		return nil, "", err
	}
	if r.Security.PrinterCert == "" {
		return nil, "", errors.New("mqtt: missing 'printer_cert' in exchange response")
	}
	pub, err := secure.ParsePublicKey(r.Security.PrinterCert)
	if err != nil {
		return nil, r.Security.PrinterCert, err
	}
	return pub, r.Security.PrinterCert, nil
}

// SecurityErrnos are the reply error codes (im5.s / pv9.e) on which the app
// refreshes its app certificate, re-runs the exchange and retries the command
// signed. 84033543 is "MQTT Command verification failed"; 84033545 is
// "need reset device pub key".
var SecurityErrnos = map[int]bool{84033543: true, 84033544: true, 84033545: true, 84033547: true, 84033548: true}

// IsSecurityError reports whether a reply asks for the secure-channel exchange.
func IsSecurityError(r *Response) bool {
	return r != nil && (SecurityErrnos[r.Errno] || SecurityErrnos[r.ErrCode])
}

// AppCertMaterial is the cloud-issued app certificate the exchange installs on
// the printer (see cloud.AppCert).
type AppCertMaterial struct {
	// CertPEM is the full chain string returned by the cert endpoint; it is sent
	// verbatim as security/app_cert_install app_cert.
	CertPEM string
	// CRLPEM is the joined CRL (optional, but printers such as the A1 mini
	// answer 0x05024007 when it is missing).
	CRLPEM string
	// MQTTCertID is "<serial hex>CN=<issuer CN>", the id the printer lists in
	// app_cert_list and that goes into the signature header.
	MQTTCertID string
	Key        *rsa.PrivateKey
}

// SecureStatus describes the exchange outcome.
type SecureStatus struct {
	Serial       string   `json:"serial"`
	CertID       string   `json:"certId"`
	Installed    bool     `json:"installed"`    // cert id was already in app_cert_list
	PrinterCert  string   `json:"printerCert"`  // PEM from app_cert_install
	CertIDs      []string `json:"certIds"`      // what the printer listed
	FieldEncrypt bool     `json:"fieldEncrypt"` // printer cert parsed, *_enc fields enabled
}

// EstablishSecure runs the app's certificate exchange against serial:
// security/app_cert_list, then security/app_cert_install when our cert id is
// missing or we still lack the printer certificate, and installs the resulting
// SecureChannel so every later command is signed (and sensitive fields
// encrypted). The two bootstrap commands are always sent in plaintext.
func (c *Client) EstablishSecure(ctx context.Context, serial string, m AppCertMaterial) (*SecureStatus, error) {
	if m.Key == nil || m.MQTTCertID == "" || m.CertPEM == "" {
		return nil, errors.New("mqtt: app certificate material incomplete")
	}
	prev := c.Secure(serial)
	c.SetSecure(serial, nil)
	st := &SecureStatus{Serial: serial, CertID: m.MQTTCertID}
	list, err := c.Send(ctx, serial, AppCertList())
	if err != nil {
		c.SetSecure(serial, prev)
		return nil, fmt.Errorf("app_cert_list: %w", err)
	}
	if err := list.Err(); err != nil {
		c.SetSecure(serial, prev)
		return nil, err
	}
	st.CertIDs = ParseCertIDs(list.Payload)
	for _, id := range st.CertIDs {
		if id == m.MQTTCertID {
			st.Installed = true
		}
	}
	var printerPub *rsa.PublicKey
	if prev != nil && prev.PrinterCert != nil && st.Installed {
		printerPub = prev.PrinterCert
		st.PrinterCert = prev.PrinterCertPEM
	} else {
		var crl *string
		if strings.TrimSpace(m.CRLPEM) != "" {
			v := m.CRLPEM
			crl = &v
		}
		inst, err := c.Send(ctx, serial, AppCertInstall(AppCertInstallParams{AppCert: m.CertPEM, Crl: crl}))
		if err != nil {
			c.SetSecure(serial, prev)
			return nil, fmt.Errorf("app_cert_install: %w", err)
		}
		if err := inst.Err(); err != nil {
			c.SetSecure(serial, prev)
			return nil, err
		}
		pub, pemStr, perr := ParsePrinterCert(inst.Payload)
		if perr != nil {
			// Signing still works without the printer key; only field encryption is lost.
			printerPub = nil
		} else {
			printerPub = pub
		}
		st.PrinterCert = pemStr
	}
	sc := &SecureChannel{Key: m.Key, CertID: m.MQTTCertID, PrinterCert: printerPub, PrinterCertPEM: st.PrinterCert}
	c.SetSecure(serial, sc)
	st.FieldEncrypt = printerPub != nil
	return st, nil
}
