package cloud

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Response `key` blob handling for GET iot-service/api/user/applications/{appKey}/cert.
//
// The app hands the base64-decoded blob to libbbl_crypto.so
// (BblCryptoEphemeralAes.wrapEncryptedPrivateKey, "must contain an IV,
// ciphertext, and GCM tag"; IotAppCert requires > 34 bytes) and then derives
// the signing key from it with the ephemeral AES session. That library is
// Virbox-packed, so two candidate layouts are supported and tried in order:
//
//  1. AES-256-GCM with the request's session key, either iv(12)‖ct‖tag(16)
//     (the deprecated BblCryptoKey.fromEncryptedPrivateKey(aesKey, iv,
//     ciphertextAndTag) shape) or nonce(12)‖tag(16)‖u32le(len)‖ct.
//  2. The desktop Bambu Studio plugin's blob: nonce(12)‖tag(16)‖u32le(len)‖ct
//     encrypted with a custom-S-box AES-256-CTR under the fixed key 00..1f,
//     counter starting at 2, plaintext "SKEY" header followed by five
//     equal-width big-endian CRT limbs (p, q, dp, dq, qinv). Documented by
//     ClusterM/open-bamboo-networking research/10.02-secrets.md and
//     tools/fetch_slicer_credentials.py.
//
// The decoded plaintext is accepted as PEM, PKCS#8/PKCS#1 DER or SKEY.

const (
	blobNonceLen  = 12
	blobTagLen    = 16
	blobLenOffset = blobNonceLen + blobTagLen // 28
	blobHeaderLen = blobLenOffset + 4         // 32

	skeyHeaderLen = 32 // magic(4) ‖ version(4) ‖ bitlen(4) ‖ 5×limb-len(4)
	skeyLimbCount = 5
)

var skeyMagic = []byte{0x59, 0x45, 0x4b, 0x53} // LE 0x534b4559

// appCertFixedKey is the desktop plugin's fixed blob key (00 01 … 1f).
var appCertFixedKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}()

// appCertSBox is the non-standard S-box used by the desktop plugin's AES.
var appCertSBox = [256]byte{
	0xC5, 0x57, 0x4D, 0x6C, 0x3A, 0x95, 0x05, 0xE0, 0xA3, 0xBA, 0x36, 0x1F, 0xEA, 0x51, 0x53, 0x3B,
	0x0E, 0x07, 0x4E, 0x64, 0x50, 0x04, 0x40, 0xE8, 0x62, 0x6E, 0x9F, 0x2D, 0x70, 0x8B, 0x28, 0x49,
	0xD5, 0xF9, 0x65, 0x8D, 0x74, 0x68, 0x7C, 0x6F, 0x0A, 0x6A, 0xB3, 0xAF, 0x38, 0xFE, 0x7E, 0x8A,
	0x47, 0x7F, 0xB0, 0x16, 0x00, 0xD4, 0x0F, 0x13, 0xC9, 0x80, 0x4A, 0xAC, 0x8C, 0x4F, 0xA7, 0x98,
	0x83, 0x94, 0x5D, 0x48, 0xB4, 0xE9, 0x30, 0x19, 0x03, 0x99, 0x25, 0xBF, 0x8E, 0x41, 0xA0, 0xE4,
	0xC3, 0xCF, 0x2C, 0xAB, 0xD2, 0x32, 0x1A, 0x0C, 0x11, 0xB5, 0x56, 0x63, 0x15, 0xA6, 0x69, 0x0B,
	0x88, 0xBB, 0x4C, 0x10, 0xCB, 0x75, 0xFA, 0x81, 0xF8, 0xCD, 0xA1, 0xD6, 0x97, 0xB7, 0x26, 0xC6,
	0x9E, 0xF1, 0x5F, 0xE5, 0xA9, 0x87, 0xC7, 0xDC, 0x8F, 0x7A, 0x86, 0x20, 0x9A, 0xD1, 0x08, 0xC2,
	0x84, 0x09, 0x33, 0x1B, 0xDD, 0x1E, 0xFD, 0x01, 0x71, 0xDA, 0x77, 0x0D, 0xD7, 0xDE, 0x93, 0xCA,
	0xA5, 0xD0, 0xE6, 0x60, 0x89, 0x37, 0xC8, 0x21, 0x59, 0x79, 0x96, 0xAD, 0x24, 0x34, 0xB9, 0x44,
	0xFC, 0xC1, 0xAE, 0xF3, 0x82, 0x46, 0x43, 0x31, 0xE3, 0x2E, 0x4B, 0xFB, 0x92, 0x55, 0xED, 0x45,
	0x76, 0x6D, 0xAA, 0x3F, 0xF5, 0x5A, 0x91, 0x78, 0x22, 0x06, 0xFF, 0xD9, 0x35, 0x7D, 0x7B, 0xDB,
	0x54, 0x12, 0x9C, 0xD8, 0xD3, 0xEE, 0x17, 0x42, 0x52, 0x3E, 0xA4, 0xE7, 0xDF, 0x9D, 0xF2, 0xF4,
	0xEF, 0x73, 0xF6, 0x5E, 0xB1, 0x5B, 0x18, 0xE2, 0x9B, 0x58, 0xA8, 0x2A, 0xE1, 0x3D, 0x90, 0xB6,
	0x1C, 0xBD, 0x61, 0xEB, 0x23, 0xA2, 0x67, 0x39, 0xF0, 0xBC, 0xB2, 0xF7, 0x85, 0x27, 0x72, 0xCC,
	0x29, 0xB8, 0x1D, 0xBE, 0x66, 0xC4, 0x2F, 0xCE, 0x14, 0x3C, 0x6B, 0xEC, 0x5C, 0x2B, 0xC0, 0x02,
}

var aesRcon = [14]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D}

func gfMul(a, b byte) byte {
	var r byte
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return r
}

// customAESExpand is the AES-256 key schedule with appCertSBox substituted.
func customAESExpand(key []byte) [15][16]byte {
	var w [60][4]byte
	for i := 0; i < 8; i++ {
		copy(w[i][:], key[4*i:4*i+4])
	}
	for i := 8; i < 60; i++ {
		t := w[i-1]
		switch {
		case i%8 == 0:
			tmp := t[0]
			t[0] = appCertSBox[t[1]] ^ aesRcon[i/8-1]
			t[1] = appCertSBox[t[2]]
			t[2] = appCertSBox[t[3]]
			t[3] = appCertSBox[tmp]
		case i%8 == 4:
			for j := range t {
				t[j] = appCertSBox[t[j]]
			}
		}
		for j := 0; j < 4; j++ {
			w[i][j] = w[i-8][j] ^ t[j]
		}
	}
	var rk [15][16]byte
	for r := 0; r < 15; r++ {
		for c := 0; c < 4; c++ {
			copy(rk[r][4*c:4*c+4], w[4*r+c][:])
		}
	}
	return rk
}

// customAESEncryptBlock encrypts one block with the custom S-box; the state is
// column-major (state[4*col+row]) and ShiftRows/MixColumns are textbook AES.
func customAESEncryptBlock(rk *[15][16]byte, in []byte) [16]byte {
	var s [16]byte
	for i := range s {
		s[i] = in[i] ^ rk[0][i]
	}
	for rnd := 1; rnd < 15; rnd++ {
		for i := range s {
			s[i] = appCertSBox[s[i]]
		}
		var t [16]byte
		for r := 0; r < 4; r++ {
			for c := 0; c < 4; c++ {
				t[4*c+r] = s[4*((c+r)%4)+r]
			}
		}
		s = t
		if rnd < 14 {
			for c := 0; c < 4; c++ {
				a0, a1, a2, a3 := s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
				s[4*c+0] = gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3
				s[4*c+1] = a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3
				s[4*c+2] = a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3)
				s[4*c+3] = gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2)
			}
		}
		for i := range s {
			s[i] ^= rk[rnd][i]
		}
	}
	return s
}

// customAESCTR XORs data with the custom-AES keystream; block i uses counter 2+i.
func customAESCTR(key, nonce, data []byte) []byte {
	rk := customAESExpand(key)
	out := make([]byte, len(data))
	ctr := make([]byte, 16)
	copy(ctr, nonce)
	for i := 0; i*16 < len(data); i++ {
		binary.BigEndian.PutUint32(ctr[12:], uint32(2+i))
		ks := customAESEncryptBlock(&rk, ctr)
		for j := 0; j < 16 && i*16+j < len(data); j++ {
			out[i*16+j] = data[i*16+j] ^ ks[j]
		}
	}
	return out
}

// splitFramedBlob parses nonce(12)‖tag(16)‖u32le(len)‖ct.
func splitFramedBlob(blob []byte) (nonce, tag, ct []byte, err error) {
	if len(blob) <= blobHeaderLen {
		return nil, nil, nil, errors.New("iotcert: framed key blob too short")
	}
	n := int(binary.LittleEndian.Uint32(blob[blobLenOffset:]))
	if n <= 0 || blobHeaderLen+n > len(blob) {
		n = len(blob) - blobHeaderLen
	}
	return blob[:blobNonceLen], blob[blobNonceLen:blobLenOffset], blob[blobHeaderLen : blobHeaderLen+n], nil
}

// parseSKEY rebuilds an RSA private key from the desktop plugin's plaintext:
// "SKEY" ‖ version ‖ bitlen ‖ 5×limb-len ‖ p ‖ q ‖ dp ‖ dq ‖ qinv.
func parseSKEY(pt []byte) (*rsa.PrivateKey, error) {
	if len(pt) < skeyHeaderLen+skeyLimbCount || !bytes.Equal(pt[:4], skeyMagic) {
		return nil, errors.New("iotcert: SKEY magic missing")
	}
	body := pt[skeyHeaderLen:]
	limbs := make([]*big.Int, skeyLimbCount)
	off := 0
	for i := range limbs {
		l := int(binary.LittleEndian.Uint32(pt[12+4*i:]))
		if l <= 0 || off+l > len(body) {
			// Fall back to equal-width limbs when the header lengths look wrong.
			if len(body)%skeyLimbCount != 0 {
				return nil, fmt.Errorf("iotcert: SKEY limb %d length %d out of range", i, l)
			}
			l = len(body) / skeyLimbCount
			off = i * l
		}
		limbs[i] = new(big.Int).SetBytes(body[off : off+l])
		off += l
	}
	p, q, dp, dq, qinv := limbs[0], limbs[1], limbs[2], limbs[3], limbs[4]
	one := big.NewInt(1)
	p1 := new(big.Int).Sub(p, one)
	q1 := new(big.Int).Sub(q, one)
	g := new(big.Int).GCD(nil, nil, p1, q1)
	lambda := new(big.Int).Mul(new(big.Int).Div(p1, g), q1)
	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, lambda)
	if d == nil {
		return nil, errors.New("iotcert: SKEY limbs do not form an RSA key")
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537},
		D:         d,
		Primes:    []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   dp,
			Dq:   dq,
			Qinv: qinv,
		},
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("iotcert: SKEY key invalid: %w", err)
	}
	return key, nil
}

// unwrapAppKeyBlob tries every known layout and returns the key plus a label
// naming the layout that worked (surfaced in AppCert.KeyLayout).
func unwrapAppKeyBlob(sessionKey, blob []byte) (*rsa.PrivateKey, string, error) {
	var errs []error
	try := func(label string, pt []byte) (*rsa.PrivateKey, string, bool) {
		k, format, err := parseAnyPrivateKey(pt)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
			return nil, "", false
		}
		return k, label + "/" + format, true
	}

	// 1a. session-key GCM, iv ‖ ct ‖ tag
	if pt, err := aesGCMOpen(sessionKey, blob); err == nil {
		if k, layout, ok := try("gcm-session-iv-ct-tag", pt); ok {
			return k, layout, nil
		}
	} else {
		errs = append(errs, fmt.Errorf("gcm-session-iv-ct-tag: %w", err))
	}
	nonce, tag, ct, err := splitFramedBlob(blob)
	if err != nil {
		return nil, "", errors.Join(append(errs, err)...)
	}
	// 1b. session-key GCM, nonce ‖ tag ‖ len ‖ ct
	re := append(append(append([]byte{}, nonce...), ct...), tag...)
	if pt, err := aesGCMOpen(sessionKey, re); err == nil {
		if k, layout, ok := try("gcm-session-framed", pt); ok {
			return k, layout, nil
		}
	} else {
		errs = append(errs, fmt.Errorf("gcm-session-framed: %w", err))
	}
	// 2. fixed-key custom AES-CTR (desktop plugin layout)
	if k, layout, ok := try("custom-ctr-fixed", customAESCTR(appCertFixedKey, nonce, ct)); ok {
		return k, layout, nil
	}
	return nil, "", errors.Join(errs...)
}
