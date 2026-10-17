package secure

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestPrivateEncryptPKCS1v15IsOpenSSLType1Block(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("1760000000000")
	ct, err := PrivateEncryptPKCS1v15(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != key.Size() {
		t.Fatalf("ciphertext length %d, want %d", len(ct), key.Size())
	}
	// Public "decrypt": m = c^e mod n must be 00 01 FF..FF 00 || msg.
	em := new(big.Int).Exp(new(big.Int).SetBytes(ct), big.NewInt(int64(key.E)), key.N).FillBytes(make([]byte, key.Size()))
	if em[0] != 0 || em[1] != 1 {
		t.Fatalf("bad block type header % x", em[:2])
	}
	i := 2
	for ; i < len(em) && em[i] == 0xFF; i++ {
	}
	if i < 10 || em[i] != 0 {
		t.Fatalf("bad padding terminator at %d", i)
	}
	if got := string(em[i+1:]); got != string(msg) {
		t.Fatalf("recovered %q, want %q", got, msg)
	}
}

func TestSignSHA256VerifiesWithStdlib(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := []byte(`{"print":{"command":"pause"}}`)
	sig, err := SignSHA256(key, data)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, 5 /* crypto.SHA256 */, h[:], sig); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalJSONSortsNestedKeysCompactly(t *testing.T) {
	in := map[string]any{
		"user_id": "123",
		"print":   map[string]any{"sequence_id": "2001", "command": "gcode_line", "param": "G28\n", "timestamp": int64(1760000000000)},
	}
	got, err := CanonicalJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"print":{"command":"gcode_line","param":"G28\n","sequence_id":"2001","timestamp":1760000000000},"user_id":"123"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestParsePublicKeyAcceptsCertificatePEMAndBareBase64(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := marshalPKIX(&key.PublicKey)
	pub, err := ParsePublicKey(base64Std(der))
	if err != nil || pub.N.Cmp(key.N) != 0 {
		t.Fatalf("bare base64 SPKI not parsed: %v", err)
	}
}

func marshalPKIX(pub *rsa.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pub) }
func base64Std(b []byte) string                      { return base64.StdEncoding.EncodeToString(b) }
