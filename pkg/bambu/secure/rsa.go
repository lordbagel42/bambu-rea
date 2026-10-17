// Package secure reimplements the small set of libbbl_crypto operations the Handy
// app uses for cloud login, IoT request signing and secure-channel MQTT commands.
package secure

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// ParsePublicKey accepts a PEM "PUBLIC KEY"/"RSA PUBLIC KEY"/"CERTIFICATE" block or a
// bare base64 DER SubjectPublicKeyInfo and returns the RSA public key.
func ParsePublicKey(s string) (*rsa.PublicKey, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if strings.HasPrefix(s, "-----") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("secure: invalid PEM")
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			pub, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("secure: certificate key is not RSA")
			}
			return pub, nil
		case "RSA PUBLIC KEY":
			return x509.ParsePKCS1PublicKey(block.Bytes)
		}
		der = block.Bytes
	} else {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, fmt.Errorf("secure: public key is neither PEM nor base64: %w", err)
		}
		der = b
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		if k1, err1 := x509.ParsePKCS1PublicKey(der); err1 == nil {
			return k1, nil
		}
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("secure: not an RSA public key")
	}
	return pub, nil
}

// ParsePrivateKey accepts PKCS#1 or PKCS#8 PEM.
func ParsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, errors.New("secure: invalid private key PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("secure: not an RSA private key")
	}
	return priv, nil
}

// EncryptOAEPSHA256 is BblCryptoKey.encrypt(RsaPadding.PKCS1_OAEP, HashAlgorithm.SHA256).
func EncryptOAEPSHA256(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// EncryptPKCS1v15 is BblCryptoKey.encrypt(RsaPadding.PKCS1_V15), used for secure-channel
// field encryption (`<field>_enc`) with the printer certificate.
func EncryptPKCS1v15(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
}

// SignSHA256 is BblCryptoKey.sign(HashAlgorithm.SHA256) with PKCS#1 v1.5 padding.
func SignSHA256(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
}

// PrivateEncryptPKCS1v15 is OpenSSL RSA_private_encrypt with RSA_PKCS1_PADDING (type 1
// block, 0x00 0x01 0xFF.. 0x00 || data), the primitive behind
// BblCryptoKey.privateEncrypt(RsaPadding.PKCS1_V15) used for x-bbl-device-security-sign.
func PrivateEncryptPKCS1v15(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	k := priv.Size()
	if len(data) > k-11 {
		return nil, errors.New("secure: message too long for RSA key")
	}
	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x01
	for i := 2; i < k-len(data)-1; i++ {
		em[i] = 0xFF
	}
	em[k-len(data)-1] = 0x00
	copy(em[k-len(data):], data)
	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, priv.D, priv.N)
	out := make([]byte, k)
	c.FillBytes(out)
	return out, nil
}

// CanonicalJSON renders v the way the app's jmv.g() does before signing: objects with
// keys sorted lexicographically, no whitespace. encoding/json already sorts map keys and
// emits compact output, so this is a thin wrapper that forces map-based ordering.
func CanonicalJSON(v any) ([]byte, error) {
	norm, err := normalize(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(norm)
}

func normalize(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			n, err := normalize(t[k])
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			n, err := normalize(e)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case nil, string, bool, float64, float32, int, int64, int32, json.Number:
		return t, nil
	default:
		// Structs and other values: round-trip through JSON to get maps/slices.
		b, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		var generic any
		if err := json.Unmarshal(b, &generic); err != nil {
			return nil, err
		}
		return normalize(generic)
	}
}
