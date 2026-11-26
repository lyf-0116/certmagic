package certmagic

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

const certWithOCSPServer = `-----BEGIN CERTIFICATE-----
MIIBgjCCASegAwIBAgICIAAwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMHVGVzdCBD
QTAeFw0yMzAxMDExMjAwMDBaFw0yMzAyMDExMjAwMDBaMCAxHjAcBgNVBAMTFU9D
U1AgVGVzdCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoe
I/bjo34qony8LdRJD+Jhuk8/S8YHXRHl6rH9t5VFCFtX8lIPN/Ll1zCrQ2KB3Wlb
fxSgiQyLrCpZyrdhVPSjXzBdMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU+Eo3
5sST4LRrwS4dueIdGBZ5d7IwLAYIKwYBBQUHAQEEIDAeMBwGCCsGAQUFBzABhhBv
Y3NwLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDg94xY/+/VepESdvTT
ykCwiWOS2aCpjyryrKpwMKkR0AIhAPc/+ZEz4W10OENxC1t+NUTvS8JbEGOwulkZ
z9yfaLuD
-----END CERTIFICATE-----`

const certWithoutOCSPServer = `-----BEGIN CERTIFICATE-----
MIIBUzCB+aADAgECAgIgADAKBggqhkjOPQQDAjASMRAwDgYDVQQDEwdUZXN0IENB
MB4XDTIzMDEwMTEyMDAwMFoXDTIzMDIwMTEyMDAwMFowIDEeMBwGA1UEAxMVT0NT
UCBUZXN0IENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEih4j
9uOjfiqifLwt1EkP4mG6Tz9LxgddEeXqsf23lUUIW1fyUg838uXXMKtDYoHdaVt/
FKCJDIusKlnKt2FU9KMxMC8wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBT4Sjfm
xJPgtGvBLh254h0YFnl3sjAKBggqhkjOPQQDAgNJADBGAiEA3rWetLGblfSuNZKf
5CpZxhj3A0BjEocEh+2P+nAgIdUCIQDIgptabR1qTLQaF2u0hJsEX2IKuIUvYWH3
6Lb92+zIHg==
-----END CERTIFICATE-----`

// certKey is the private key for both certWithOCSPServer and
// certWithoutOCSPServer.
const certKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINnVcgrSNh4HlThWlZpegq14M8G/p9NVDtdVjZrseUGLoAoGCCqGSM49
AwEHoUQDQgAEih4j9uOjfiqifLwt1EkP4mG6Tz9LxgddEeXqsf23lUUIW1fyUg83
8uXXMKtDYoHdaVt/FKCJDIusKlnKt2FU9A==
-----END EC PRIVATE KEY-----`

// caCert is the issuing certificate for certWithOCSPServer and
// certWithoutOCSPServer.
const caCert = `-----BEGIN CERTIFICATE-----
MIIBazCCARGgAwIBAgICEAAwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMHVGVzdCBD
QTAeFw0yMzAxMDExMjAwMDBaFw0yMzAyMDExMjAwMDBaMBIxEDAOBgNVBAMTB1Rl
c3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASdKexSor/aeazDM57UHhAX
rCkJxUeF2BWf0lZYCRxc3f0GdrEsVvjJW8+/E06eAzDCGSdM/08Nvun1nb6AmAlt
o1cwVTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwkwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQU+Eo35sST4LRrwS4dueIdGBZ5d7IwCgYIKoZI
zj0EAwIDSAAwRQIgGbA39+kETTB/YMLBFoC2fpZe1cDWfFB7TUdfINUqdH4CIQCR
ByUFC8A+hRNkK5YNH78bgjnKk/88zUQF5ONy4oPGdQ==
-----END CERTIFICATE-----`

const caKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDJ59ptjq3MzILH4zn5IKoH1sYn+zrUeq2kD8+DD2x+OoAoGCCqGSM49
AwEHoUQDQgAEnSnsUqK/2nmswzOe1B4QF6wpCcVHhdgVn9JWWAkcXN39BnaxLFb4
yVvPvxNOngMwwhknTP9PDb7p9Z2+gJgJbQ==
-----END EC PRIVATE KEY-----`

func TestStapleOCSP(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}

	t.Run("disabled", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		config := OCSPConfig{DisableStapling: true}
		err := stapleOCSP(ctx, config, storage, &cert, nil)
		if err != nil {
			t.Error("unexpected error:", err)
		} else if cert.Certificate.OCSPStaple != nil {
			t.Error("unexpected OCSP staple")
		}
	})
	t.Run("no OCSP server", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithoutOCSPServer, certKey)
		err := stapleOCSP(ctx, OCSPConfig{}, storage, &cert, nil)
		if !errors.Is(err, ErrNoOCSPServerSpecified) {
			t.Error("expected ErrNoOCSPServerSpecified in error", err)
		}
	})

	// Start an OCSP responder test server.
	responses := make(map[string][]byte)
	responder := startOCSPResponder(t, responses)
	t.Cleanup(responder.Close)

	ca := mustMakeCertificate(t, caCert, caKey)

	// The certWithOCSPServer certificate has a bogus ocsp.example.com endpoint.
	// Use the ResponderOverrides option to point to the test server instead.
	config := OCSPConfig{
		ResponderOverrides: map[string]string{
			"ocsp.example.com": responder.URL,
		},
	}

	t.Run("ok", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		tpl := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: cert.Leaf.SerialNumber,
		}
		r, err := ocsp.CreateResponse(
			ca.Leaf, ca.Leaf, tpl, ca.PrivateKey.(crypto.Signer))
		if err != nil {
			t.Fatal("couldn't create OCSP response", err)
		}
		responses[cert.Leaf.SerialNumber.String()] = r

		bundle := []byte(certWithOCSPServer + "\n" + caCert)
		err = stapleOCSP(ctx, config, storage, &cert, bundle)
		if err != nil {
			t.Error("unexpected error:", err)
		} else if !bytes.Equal(cert.Certificate.OCSPStaple, r) {
			t.Error("expected OCSP response to be stapled to certificate")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		tpl := ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: cert.Leaf.SerialNumber,
		}
		r, err := ocsp.CreateResponse(
			ca.Leaf, ca.Leaf, tpl, ca.PrivateKey.(crypto.Signer))
		if err != nil {
			t.Fatal("couldn't create OCSP response", err)
		}
		responses[cert.Leaf.SerialNumber.String()] = r

		bundle := []byte(certWithOCSPServer + "\n" + caCert)
		err = stapleOCSP(ctx, config, storage, &cert, bundle)
		if err != nil {
			t.Error("unexpected error:", err)
		} else if cert.Certificate.OCSPStaple != nil {
			t.Error("revoked OCSP response should not be stapled")
		}
	})
	t.Run("no issuing cert", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		err := stapleOCSP(ctx, config, storage, &cert, nil)
		expected := "no OCSP stapling for [ocsp test certificate]: " +
			"no URL to issuing certificate"
		if err == nil || err.Error() != expected {
			t.Errorf("expected error %q but got %q", expected, err)
		}
	})
}

func TestValidateOCSPResponder(t *testing.T) {
	issuer := mustMakeCertificate(t, caCert, caKey).Leaf

	tests := []struct {
		name    string
		resp    *ocsp.Response
		wantErr string
	}{
		{
			name: "issuer signed response with no embedded cert",
			resp: &ocsp.Response{Certificate: nil},
		},
		{
			name: "embedded responder cert is issuer cert",
			resp: &ocsp.Response{Certificate: issuer},
		},
		{
			name: "delegated responder with OCSP signing eku",
			resp: &ocsp.Response{Certificate: &x509.Certificate{
				Subject: pkix.Name{CommonName: "Delegated OCSP Responder"},
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageOCSPSigning,
				},
			}},
		},
		{
			name: "delegated responder without OCSP signing eku",
			resp: &ocsp.Response{Certificate: &x509.Certificate{
				Subject:     pkix.Name{CommonName: "Not Authorized"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}},
			wantErr: "does not carry id-kp-OCSPSigning",
		},
		{
			name: "delegated responder with empty eku",
			resp: &ocsp.Response{Certificate: &x509.Certificate{
				Subject: pkix.Name{CommonName: "No EKU"},
			}},
			wantErr: "does not carry id-kp-OCSPSigning",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOCSPResponder(tc.resp, issuer)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestStapleOCSPDelegatedResponderAuthorization(t *testing.T) {
	now := time.Now().Add(-1 * time.Hour)

	issuerCert, issuerKey, issuerPEM := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             now,
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)

	issuedCert, issuedKey, issuedPEM := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "victim.example"},
		DNSNames:     []string{"victim.example"},
		NotBefore:    now,
		NotAfter:     now.Add(30 * 24 * time.Hour),
		OCSPServer:   []string{"http://ocsp.example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, issuerCert, issuerKey)

	issuedKeyPEM, err := PEMEncodePrivateKey(issuedKey)
	if err != nil {
		t.Fatalf("encoding issued certificate key: %v", err)
	}
	bundle := append(append([]byte{}, issuedPEM...), issuerPEM...)

	tests := []struct {
		name                 string
		responderSerial      int64
		responderCommonName  string
		responderExtKeyUsage []x509.ExtKeyUsage
		wantErr              string
		wantStaple           bool
	}{
		{
			name:                "authorized OCSP responder is stapled",
			responderSerial:     3,
			responderCommonName: "authorized-responder.example",
			responderExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageOCSPSigning,
			},
			wantStaple: true,
		},
		{
			name:                 "same issuer server auth responder is rejected",
			responderSerial:      4,
			responderCommonName:  "server-auth-responder.example",
			responderExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantErr:              "does not carry id-kp-OCSPSigning",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responderCert, responderKey, _ := mustIssueTestCertificate(t, &x509.Certificate{
				SerialNumber: big.NewInt(tc.responderSerial),
				Subject:      pkix.Name{CommonName: tc.responderCommonName},
				DNSNames:     []string{tc.responderCommonName},
				NotBefore:    now,
				NotAfter:     now.Add(30 * 24 * time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  tc.responderExtKeyUsage,
			}, issuerCert, issuerKey)

			responseBytes, err := ocsp.CreateResponse(issuerCert, responderCert, ocsp.Response{
				Status:       ocsp.Good,
				SerialNumber: issuedCert.SerialNumber,
				ThisUpdate:   time.Now().Add(-5 * time.Minute).UTC(),
				NextUpdate:   time.Now().Add(2 * time.Hour).UTC(),
				Certificate:  responderCert,
			}, responderKey)
			if err != nil {
				t.Fatalf("creating OCSP response: %v", err)
			}

			responder := startOCSPResponder(t, map[string][]byte{
				issuedCert.SerialNumber.String(): responseBytes,
			})
			defer responder.Close()

			cert, err := makeCertificate(issuedPEM, issuedKeyPEM)
			if err != nil {
				t.Fatalf("making issued certificate: %v", err)
			}

			config := OCSPConfig{
				ResponderOverrides: map[string]string{
					"http://ocsp.example.test": responder.URL,
				},
			}
			storage := &FileStorage{Path: t.TempDir()}

			err = stapleOCSP(context.Background(), config, storage, &cert, bundle)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
				if cert.Certificate.OCSPStaple != nil {
					t.Fatal("unexpected OCSP staple for unauthorized responder")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantStaple && !bytes.Equal(cert.Certificate.OCSPStaple, responseBytes) {
				t.Fatal("expected OCSP response to be stapled")
			}
		})
	}
}

func TestStapleOCSPCachedResponseValidation(t *testing.T) {
	ctx := context.Background()
	cert, bundle, issuerCert, issuerKey := newOCSPTestFixture(t)
	now := time.Now()

	validResponse, err := ocsp.CreateResponse(issuerCert, issuerCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.Leaf.SerialNumber,
		ThisUpdate:   now.Add(-time.Hour).UTC(),
		NextUpdate:   now.Add(24 * time.Hour).UTC(),
	}, issuerKey)
	if err != nil {
		t.Fatalf("creating valid OCSP response: %v", err)
	}

	wrongSerialResponse, err := ocsp.CreateResponse(issuerCert, issuerCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(999),
		ThisUpdate:   now.Add(-time.Hour).UTC(),
		NextUpdate:   now.Add(24 * time.Hour).UTC(),
	}, issuerKey)
	if err != nil {
		t.Fatalf("creating wrong-serial OCSP response: %v", err)
	}

	responderCert, responderKey, _ := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "unauthorized-responder.example"},
		DNSNames:     []string{"unauthorized-responder.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, issuerCert, issuerKey)
	unauthorizedResponse, err := ocsp.CreateResponse(issuerCert, responderCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.Leaf.SerialNumber,
		ThisUpdate:   now.Add(-time.Hour).UTC(),
		NextUpdate:   now.Add(24 * time.Hour).UTC(),
		Certificate:  responderCert,
	}, responderKey)
	if err != nil {
		t.Fatalf("creating unauthorized-responder OCSP response: %v", err)
	}

	tamperedResponse := append([]byte(nil), validResponse...)
	tamperedResponse[len(tamperedResponse)-1] ^= 0x01

	tests := []struct {
		name   string
		cached []byte
	}{
		{name: "tampered signature", cached: tamperedResponse},
		{name: "unauthorized responder", cached: unauthorizedResponse},
		{name: "wrong serial number", cached: wrongSerialResponse},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responder := startOCSPResponder(t, map[string][]byte{
				cert.Leaf.SerialNumber.String(): validResponse,
			})
			t.Cleanup(responder.Close)

			storage := &recordingStorage{Storage: &FileStorage{Path: t.TempDir()}}
			config := OCSPConfig{
				ResponderOverrides: map[string]string{
					"http://ocsp.example.test": responder.URL,
				},
			}
			key := StorageKeys.OCSPStaple(&cert, bundle)
			if err := storage.Store(ctx, key, tc.cached); err != nil {
				t.Fatalf("storing cached OCSP response: %v", err)
			}

			testCert := cert
			if err := stapleOCSP(ctx, config, storage, &testCert, bundle); err != nil {
				t.Fatalf("stapling OCSP: %v", err)
			}
			if !bytes.Equal(testCert.Certificate.OCSPStaple, validResponse) {
				t.Fatal("expected invalid cached response to be replaced with a freshly fetched response")
			}

			deleted := false
			for _, call := range storage.calls {
				if call.name == "Delete" && len(call.args) > 0 && call.args[0] == key {
					deleted = true
					break
				}
			}
			if !deleted {
				t.Fatal("expected invalid cached OCSP response to be deleted")
			}
		})
	}
}

func TestStapleOCSPUsesUsableCachedResponseWhenRefreshFails(t *testing.T) {
	ctx := context.Background()
	cert, bundle, issuerCert, issuerKey := newOCSPTestFixture(t)
	now := time.Now()

	// This response is past the halfway refresh point, but still valid.
	cachedResponse, err := ocsp.CreateResponse(issuerCert, issuerCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.Leaf.SerialNumber,
		ThisUpdate:   now.Add(-10 * time.Hour).UTC(),
		NextUpdate:   now.Add(2 * time.Hour).UTC(),
	}, issuerKey)
	if err != nil {
		t.Fatalf("creating cached OCSP response: %v", err)
	}

	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(responder.Close)

	config := OCSPConfig{
		ResponderOverrides: map[string]string{
			"http://ocsp.example.test": responder.URL,
		},
	}
	storage := &recordingStorage{Storage: &FileStorage{Path: t.TempDir()}}
	key := StorageKeys.OCSPStaple(&cert, bundle)
	if err := storage.Store(ctx, key, cachedResponse); err != nil {
		t.Fatalf("storing cached OCSP response: %v", err)
	}

	if err := stapleOCSP(ctx, config, storage, &cert, bundle); err != nil {
		t.Fatalf("expected usable cached response to survive refresh failure: %v", err)
	}
	if !bytes.Equal(cert.Certificate.OCSPStaple, cachedResponse) {
		t.Fatal("expected usable cached response to remain stapled")
	}
}

func TestStapleOCSPKeepsAttachedResponseWhenRefreshFails(t *testing.T) {
	ctx := context.Background()
	cert, bundle, issuerCert, issuerKey := newOCSPTestFixture(t)
	now := time.Now()

	staleButUsable, err := ocsp.CreateResponse(issuerCert, issuerCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.Leaf.SerialNumber,
		ThisUpdate:   now.Add(-10 * time.Hour).UTC(),
		NextUpdate:   now.Add(2 * time.Hour).UTC(),
	}, issuerKey)
	if err != nil {
		t.Fatalf("creating attached OCSP response: %v", err)
	}
	parsed, err := ocsp.ParseResponse(staleButUsable, issuerCert)
	if err != nil {
		t.Fatalf("parsing attached OCSP response: %v", err)
	}
	cert.ocsp = parsed
	cert.Certificate.OCSPStaple = staleButUsable

	fresh, err := ocsp.CreateResponse(issuerCert, issuerCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.Leaf.SerialNumber,
		ThisUpdate:   now.Add(-time.Hour).UTC(),
		NextUpdate:   now.Add(24 * time.Hour).UTC(),
	}, issuerKey)
	if err != nil {
		t.Fatalf("creating cached OCSP response: %v", err)
	}
	tampered := append([]byte(nil), fresh...)
	tampered[len(tampered)-1] ^= 0x01

	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(responder.Close)

	config := OCSPConfig{
		ResponderOverrides: map[string]string{
			"http://ocsp.example.test": responder.URL,
		},
	}
	storage := &recordingStorage{Storage: &FileStorage{Path: t.TempDir()}}
	key := StorageKeys.OCSPStaple(&cert, bundle)
	if err := storage.Store(ctx, key, tampered); err != nil {
		t.Fatalf("storing cached OCSP response: %v", err)
	}

	if err := stapleOCSP(ctx, config, storage, &cert, bundle); err != nil {
		t.Fatalf("expected attached response to survive refresh failure: %v", err)
	}
	if !bytes.Equal(cert.Certificate.OCSPStaple, staleButUsable) {
		t.Fatal("expected attached OCSP response to remain stapled")
	}
	if cert.ocsp != parsed {
		t.Fatal("expected attached parsed OCSP response to remain unchanged")
	}
}

func newOCSPTestFixture(t *testing.T) (Certificate, []byte, *x509.Certificate, crypto.Signer) {
	t.Helper()

	now := time.Now().Add(-time.Hour)
	issuerCert, issuerKey, issuerPEM := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             now,
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)

	_, issuedKey, issuedPEM := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cached.example"},
		DNSNames:     []string{"cached.example"},
		NotBefore:    now,
		NotAfter:     now.Add(30 * 24 * time.Hour),
		OCSPServer:   []string{"http://ocsp.example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, issuerCert, issuerKey)

	issuedKeyPEM, err := PEMEncodePrivateKey(issuedKey)
	if err != nil {
		t.Fatalf("encoding issued certificate key: %v", err)
	}
	cert, err := makeCertificate(issuedPEM, issuedKeyPEM)
	if err != nil {
		t.Fatalf("making issued certificate: %v", err)
	}
	bundle := append(append([]byte{}, issuedPEM...), issuerPEM...)

	return cert, bundle, issuerCert, issuerKey
}

func mustMakeCertificate(t *testing.T, cert, key string) Certificate {
	t.Helper()
	c, err := makeCertificate([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal("couldn't make certificate:", err)
	}
	return c
}

func startOCSPResponder(
	t *testing.T, responses map[string][]byte,
) *httptest.Server {
	h := func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != "application/ocsp-request" {
			t.Errorf("unexpected request Content-Type %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		request, err := ocsp.ParseRequest(b)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(responses[request.SerialNumber.String()])
	}
	return httptest.NewServer(http.HandlerFunc(h))
}

func mustIssueTestCertificate(
	t *testing.T,
	tmpl, parent *x509.Certificate,
	parentKey crypto.Signer,
) (*x509.Certificate, crypto.Signer, []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}
	if parent == nil {
		parent = tmpl
		parentKey = priv
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, priv.Public(), parentKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	return cert, priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
