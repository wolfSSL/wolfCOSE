// go-cose is a test-only COSE_Sign1 oracle for wolfCOSE interoperability.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const (
	maxMessageSize   = 2048
	p256DERBase64    = "MHcCAQEEIAMc7GQ5oxpE/Jrk2S+fxT6IzdQIVBb7f+wh1i6ief93oAoGCCqGSM49AwEHoUQDQgAEhw4Ot5NqlZzyjFDnvmqHuTN0VBBy4ishX5BHf8i5xiC3b9tvdsQWHhXuHaHAG7QJXLf+TmhWSrFKoXYhOMYjAA=="
	p384DERBase64    = "MIGkAgEBBDAvGEQRwzLQEBHEF6ef6zTaXVmVKjAuyLHwF7hwePU8SthzTfXyr4C7EcZcLd50B+qgBwYFK4EEACKhZANiAAQzy1Ay4XqFz0KgZ3yI/v0cgMJs/r1jQJkDY/dxdYzh0sOiRC4Vsa5D5vJF7QZ/y3lY/fcczt8LQ1UgqW/1GzcPCg3hjvz8YdwQaAl1dBlu0leaENlFa1RpqFctdIDwfzs="
	p521DERBase64    = "MIHcAgEBBEIAMQVJARBEq2+Rk7x3HhdG5vajr/BYSRa9SDQriGnvgb5MqVe0DYCe0IRpqCSa1DuiYy0j7pacTKcOq1ix6ACqPNygBwYFK4EEACOhgYkDgYYABAEUBc7nKRl4asKL6IO3N54bido/CDlCBe6j02QK4TAPE0kAiT1+MdT5fZ+oSdmjFfqURVBRbfrpUp1hSvk7gtdqrgHD85atSD7LLpPVWyJT9Qc2PzQAx7SxkT/iMJ3VTHU0IeMQ4T7hFB/SFoy+BKW5tcb+wy084jZLGm/Rf4DgH7bQjA=="
	rsaDERBase64     = "MIIEowIBAAKCAQEA08O/IxZ1M9hFJUkpwee9cQkiPcY+Yyv9o5yG9IxZWv3UkRL6Bn/GpjCGbf+xMaeOvElmmJ/moskhEqFXN8dI09QlK3JJ+Bnop6gqW7MmZ8lNiYyBCdQkB1336evp/pTCBQ1Zkq6cYIqU9b4r4g1C9oRkH1Q92R3xZJbkqsDRzidtFQQIcRBNwUrUgmNNikfGpUE4Ylwk7G9p/v+emMEkAR8k3kE0ZtK1xmOVIzX5cLXKgYvY9rvfONchDuJVIuiatw0FGd/Ih8ASACnJD0au6C9m7tI5LA2Wt8J2+qWXCdyr/BtTfqNQSAmcZ8rsCulHPcK/T2hNYHbuRQiLWDPLHwIDAQABAoIBAEF75J1LEo8nr6oqB7momdJcirQjm6M7NUHk4263/+G9YIBEKADefmVh2BAn43mBYQgkgo9r0vw/yfRi4/+hpomqrpvSycDo8iL2Q7L7oUKy40FHq5eIfGOy0TkK9N7+zUiWqj5LtJu9/vZHCnbqtuxYYEW33TBIrB748llDKx3eTy/7mRrHYqZMS8fT1kH87FNOf5P0wk1HehsUER++oN3ZjfZq8+VlRa7vLA+5JL7n+YntGL2Nmm7sxVu0OWsmQpguUcYerfJnjgdJ3ZONp0d0Ocj3KYMZLS/X5iIVqt8DS33G5GAWSPakTAZhCxZFr4JsZOduMTl15P9IXMD5EIECgYEA8GiqvCA/Op82Yke4IhEH3vbPAIK5GfayiS/mt/f+f7eK4/tPhLsc10XrLveocw6HCBozxtxDLS++qtTbR81o5JcDAowBm5I2+KqOBnoKx9sf1Xfdy3+Ky5CxjV2rd2OVP+K36AlQZLgByOu+oxfaZm3xnabcO58wj8QRyXprd38CgYEA4X+FRNupUQI1xLbr+IssEZ3jSegFMK22hPekz3AhWUXIwSB5wQxHp2x5xqrRTWMoqkcf2ZRkIXfjYOxSH1ro0BdJRYYBSq5fiMNhvjg4wmEE8RLlvnb+OtTxwylfHfLAQOjTfSfulWaU6sT4vMSp5piKYCNxTnf+w+YHJzVmfGECgYEAtjYeccffJIdXqNXC8c8GsC9QZYqu0MbyOphbvkPwWMy8MF9hvbA0A9Wykz6SJeJ05ec2Jxr6r1zonoIGUT2WqurqFRwYe9kuYPqj+rS1RxUF472eFYbto6xfZk4Aj9SiYnFsAipNDImKkMZdDzAdEFV0M5EsiuP04oIxGQv4N/ECgYALDF9wNz79fBk8USYQoGkBV/YJ6fdPIkO+EhAeJcVMhXHHnJq6jap5FoSE6luk6gXVCfUSiQW66g/W8N05MhAUGf/6Cw3HJfICVmhUlJabV3uRgDaHdXcRVNufj0hcxEcNJxstl6ZF5afINOxm+0/Dv5eQDEyB5rkxyfRxxFkIIQKBgGKwO2n0SHx7L3Qoi57jsZ9BHxG5rDdgJZRR+rq3SpZG5fzm32YDKaAMMoWo7PQBhxkwz9VI/SaFZxSur3ZOTwf6qQZ0C+eYnYVd/nexWnbVBHPgQqWaN5iwLw+xavM+Nv5FvGWG+89Fpbil4f7maYhZdB/ukbq1/9HpV7/ME3ZL"
	ed25519DERBase64 = "MC4CAQAwBQYDK2VwBCIEIDUFZtjEKnpzRgSwQKsbaQrZ/gqFGV02pGAVbpkj34pu"
	psaProfile       = "tag:psacertified.org,2023:psa#tfm"
	psaSign1Hex      = "d28443a10126a0590100a819010058210102020202020202020202020202" +
		"0202020202020202020202020202020202020219095c5820000000000000" +
		"00000000000000000000000000000000000000000000000000000a582001" +
		"010101010101010101010101010101010101010101010101010101010101" +
		"0119095a1a7fffffff19095b19300019010978217461673a707361636572" +
		"7469666965642e6f72672c323032333a7073612374666d19010c48000000" +
		"000000000019095f81a30558200404040404040404040404040404040404" +
		"040404040404040404040404040404025820030303030303030303030303" +
		"0303030303030303030303030303030303030303016450526f545840786e" +
		"937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff" +
		"80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e" +
		"8e5a"
)

type keyKind uint8

const (
	keyEC keyKind = iota
	keyRSA
	keyEd25519
)

type interopCase struct {
	alg      cose.Algorithm
	keyDER   string
	keyKind  keyKind
	external []byte
	untagged bool
}

var payload = []byte("wolfCOSE<->go-cose COSE_Sign1 interoperability")
var externalAAD = []byte("wolfCOSE<->go-cose external AAD")

var cases = map[string]interopCase{
	"es256":          {cose.AlgorithmES256, p256DERBase64, keyEC, nil, false},
	"es384":          {cose.AlgorithmES384, p384DERBase64, keyEC, nil, false},
	"es512":          {cose.AlgorithmES512, p521DERBase64, keyEC, nil, false},
	"ps256":          {cose.AlgorithmPS256, rsaDERBase64, keyRSA, nil, false},
	"ps384":          {cose.AlgorithmPS384, rsaDERBase64, keyRSA, nil, false},
	"ps512":          {cose.AlgorithmPS512, rsaDERBase64, keyRSA, nil, false},
	"ed25519":        {cose.AlgorithmEdDSA, ed25519DERBase64, keyEd25519, nil, false},
	"es256-aad":      {cose.AlgorithmES256, p256DERBase64, keyEC, externalAAD, false},
	"es256-untagged": {cose.AlgorithmES256, p256DERBase64, keyEC, nil, true},
}

var psaSign1X = []byte{
	0x4e, 0x5e, 0x22, 0x09, 0x9e, 0x3b, 0xce, 0xb4,
	0x5b, 0x44, 0x6d, 0x13, 0x55, 0xfd, 0x1d, 0xc3,
	0xb5, 0x45, 0x94, 0x7b, 0x6f, 0xd7, 0xc1, 0xc8,
	0x9d, 0x88, 0x67, 0x98, 0xc3, 0x72, 0x6e, 0x8f,
}

var psaSign1Y = []byte{
	0x80, 0xd7, 0x0b, 0x84, 0x0b, 0x25, 0x6a, 0xac,
	0x34, 0xa6, 0x2e, 0xde, 0x10, 0x43, 0x36, 0x4f,
	0x04, 0x40, 0x95, 0xf0, 0x03, 0x47, 0x4b, 0x91,
	0xe0, 0x18, 0x20, 0x92, 0xaf, 0xb1, 0x3f, 0x2e,
}

func lookupCase(name string) (interopCase, error) {
	testCase, ok := cases[name]
	if !ok {
		return interopCase{}, fmt.Errorf("unknown case %q", name)
	}

	return testCase, nil
}

func privateKey(testCase interopCase) (crypto.Signer, error) {
	der, err := base64.StdEncoding.DecodeString(testCase.keyDER)
	if err != nil {
		return nil, fmt.Errorf("decode fixed key: %w", err)
	}

	switch testCase.keyKind {
	case keyEC:
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse fixed EC key: %w", err)
		}
		return key, nil
	case keyRSA:
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse fixed RSA key: %w", err)
		}
		return key, nil
	case keyEd25519:
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse fixed Ed25519 key: %w", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parse fixed Ed25519 key: unexpected type %T", key)
		}
		return edKey, nil
	default:
		return nil, fmt.Errorf("unsupported key kind %d", testCase.keyKind)
	}
}

func newSigner(testCase interopCase) (cose.Signer, error) {
	key, err := privateKey(testCase)
	if err != nil {
		return nil, err
	}

	signer, err := cose.NewSigner(testCase.alg, key)
	if err != nil {
		return nil, fmt.Errorf("create %s signer: %w", testCase.alg, err)
	}

	return signer, nil
}

func newVerifier(testCase interopCase) (cose.Verifier, error) {
	key, err := privateKey(testCase)
	if err != nil {
		return nil, err
	}

	verifier, err := cose.NewVerifier(testCase.alg, key.Public())
	if err != nil {
		return nil, fmt.Errorf("create %s verifier: %w", testCase.alg, err)
	}

	return verifier, nil
}

func sign(testCase interopCase) error {
	signer, err := newSigner(testCase)
	if err != nil {
		return err
	}

	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: testCase.alg,
		},
	}
	var encoded []byte
	if testCase.untagged {
		encoded, err = cose.Sign1Untagged(rand.Reader, signer, headers, payload,
			testCase.external)
	} else {
		encoded, err = cose.Sign1(rand.Reader, signer, headers, payload,
			testCase.external)
	}
	if err != nil {
		return fmt.Errorf("sign %s COSE_Sign1: %w", testCase.alg, err)
	}

	written, err := os.Stdout.Write(encoded)
	if err != nil {
		return fmt.Errorf("write COSE_Sign1: %w", err)
	}
	if written != len(encoded) {
		return fmt.Errorf("write COSE_Sign1: wrote %d of %d bytes", written,
			len(encoded))
	}

	return nil
}

func verifyTagged(encoded []byte, testCase interopCase, verifier cose.Verifier) error {
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(encoded); err != nil {
		return fmt.Errorf("decode tagged COSE_Sign1: %w", err)
	}
	if err := message.Verify(testCase.external, verifier); err != nil {
		return fmt.Errorf("verify tagged COSE_Sign1: %w", err)
	}
	if !bytes.Equal(message.Payload, payload) {
		return fmt.Errorf("verify tagged COSE_Sign1: payload mismatch")
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 0x01
	var invalid cose.Sign1Message
	if err := invalid.UnmarshalCBOR(tampered); err == nil {
		if err := invalid.Verify(testCase.external, verifier); err == nil {
			return fmt.Errorf("verify tagged COSE_Sign1: accepted a tampered signature")
		}
	}

	return nil
}

func verifyUntagged(encoded []byte, testCase interopCase, verifier cose.Verifier) error {
	var message cose.UntaggedSign1Message
	if err := message.UnmarshalCBOR(encoded); err != nil {
		return fmt.Errorf("decode untagged COSE_Sign1: %w", err)
	}
	if err := message.Verify(testCase.external, verifier); err != nil {
		return fmt.Errorf("verify untagged COSE_Sign1: %w", err)
	}
	if !bytes.Equal(message.Payload, payload) {
		return fmt.Errorf("verify untagged COSE_Sign1: payload mismatch")
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 0x01
	var invalid cose.UntaggedSign1Message
	if err := invalid.UnmarshalCBOR(tampered); err == nil {
		if err := invalid.Verify(testCase.external, verifier); err == nil {
			return fmt.Errorf("verify untagged COSE_Sign1: accepted a tampered signature")
		}
	}

	return nil
}

func runVerify(testCase interopCase) error {
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, maxMessageSize+1))
	if err != nil {
		return fmt.Errorf("read COSE_Sign1: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maxMessageSize {
		return fmt.Errorf("read COSE_Sign1: invalid message length %d", len(encoded))
	}

	verifier, err := newVerifier(testCase)
	if err != nil {
		return err
	}
	if testCase.untagged {
		return verifyUntagged(encoded, testCase, verifier)
	}

	return verifyTagged(encoded, testCase, verifier)
}

func verifyPSAAttestation() error {
	encoded, err := hex.DecodeString(psaSign1Hex)
	if err != nil {
		return fmt.Errorf("decode RFC 9783 token: %w", err)
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(psaSign1X),
		Y:     new(big.Int).SetBytes(psaSign1Y),
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		return fmt.Errorf("create PSA ES256 verifier: %w", err)
	}

	var message cose.Sign1Message
	if err = message.UnmarshalCBOR(encoded); err != nil {
		return fmt.Errorf("decode RFC 9783 COSE_Sign1: %w", err)
	}
	if err = message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("verify RFC 9783 COSE_Sign1: %w", err)
	}

	var claims map[int64]interface{}
	if err = cbor.Unmarshal(message.Payload, &claims); err != nil {
		return fmt.Errorf("decode RFC 9783 EAT claims: %w", err)
	}

	expectedUEID := append([]byte{0x01}, bytes.Repeat([]byte{0x02}, 32)...)
	ueid, ok := claims[256].([]byte)
	if !ok || !bytes.Equal(ueid, expectedUEID) {
		return fmt.Errorf("decode RFC 9783 EAT claims: UEID mismatch")
	}

	nonce, ok := claims[10].([]byte)
	if !ok || !bytes.Equal(nonce, bytes.Repeat([]byte{0x01}, 32)) {
		return fmt.Errorf("decode RFC 9783 EAT claims: nonce mismatch")
	}

	profile, ok := claims[265].(string)
	if !ok || profile != psaProfile {
		return fmt.Errorf("decode RFC 9783 EAT claims: profile mismatch")
	}

	bootSeed, ok := claims[268].([]byte)
	if !ok || !bytes.Equal(bootSeed, make([]byte, 8)) {
		return fmt.Errorf("decode RFC 9783 EAT claims: boot seed mismatch")
	}

	return nil
}

func main() {
	var err error

	if len(os.Args) == 2 && os.Args[1] == "psa" {
		err = verifyPSAAttestation()
	} else if len(os.Args) == 3 {
		var testCase interopCase
		testCase, err = lookupCase(os.Args[2])
		if err == nil {
			switch os.Args[1] {
			case "sign":
				err = sign(testCase)
			case "verify":
				err = runVerify(testCase)
			default:
				err = fmt.Errorf("unknown mode %q", os.Args[1])
			}
		}
	} else {
		err = fmt.Errorf("usage: go_cose_oracle sign|verify case, or go_cose_oracle psa")
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "go-cose interop:", err)
		os.Exit(1)
	}
}
