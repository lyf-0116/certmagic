// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package certmagic

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestGetCertificate(t *testing.T) {
	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c}

	// create a test connection for conn.LocalAddr()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	conn, _ := net.Dial("tcp", l.Addr().String())
	if conn == nil {
		t.Errorf("failed to create a test connection")
	}
	defer conn.Close()

	hello := &tls.ClientHelloInfo{ServerName: "example.com", Conn: conn}
	helloSub := &tls.ClientHelloInfo{ServerName: "sub.example.com", Conn: conn}
	helloNoSNI := &tls.ClientHelloInfo{Conn: conn}
	helloNoMatch := &tls.ClientHelloInfo{ServerName: "nomatch", Conn: conn}

	// When cache is empty
	if cert, err := cfg.GetCertificate(hello); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty, got: %v", cert)
	}
	if cert, err := cfg.GetCertificate(helloNoSNI); err == nil {
		t.Errorf("GetCertificate should return error when cache is empty even if server name is blank, got: %v", cert)
	}

	// When cache has one certificate in it
	firstCert := Certificate{Names: []string{"example.com"}, Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"example.com"}}}}
	c.cacheCertificate(firstCert)
	if cert, err := cfg.GetCertificate(hello); err != nil {
		t.Errorf("Got an error but shouldn't have, when cert exists in cache: %v", err)
	} else if cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("Got wrong certificate with exact match; expected 'example.com', got: %v", cert)
	}
	if _, err := cfg.GetCertificate(helloNoSNI); err == nil {
		t.Errorf("Did not get an error with no SNI and no DefaultServerName, but should have: %v", err)
	}

	// When retrieving wildcard certificate
	wildcardCert := Certificate{
		Names:       []string{"*.example.com"},
		Certificate: tls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"*.example.com"}}},
		hash:        "(don't overwrite the first one)",
	}
	c.cacheCertificate(wildcardCert)
	if cert, err := cfg.GetCertificate(helloSub); err != nil {
		t.Errorf("Didn't get wildcard cert, got: cert=%v, err=%v ", cert, err)
	} else if cert.Leaf.DNSNames[0] != "*.example.com" {
		t.Errorf("Got wrong certificate, expected wildcard: %v", cert)
	}

	// When cache is NOT empty but there's no SNI
	if _, err := cfg.GetCertificate(helloNoSNI); err == nil {
		t.Errorf("Expected TLS allert when no SNI and no DefaultServerName, but got: %v", err)
	}

	// When no certificate matches, raise an alert
	if _, err := cfg.GetCertificate(helloNoMatch); err == nil {
		t.Errorf("Expected an error when no certificate matched the SNI, got: %v", err)
	}

	// When default SNI is set and SNI is missing, retrieve default cert
	cfg.DefaultServerName = "example.com"
	if cert, err := cfg.GetCertificate(helloNoSNI); err != nil {
		t.Errorf("Got an error with no SNI with DefaultServerName, but shouldn't have: %v", err)
	} else if cert == nil || cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("Expected default cert, got: %v", cert)
	}

	// When default SNI is set and SNI is missing but IP address matches, retrieve IP cert
	ipCert := Certificate{
		Names:       []string{"127.0.0.1"},
		Certificate: tls.Certificate{Leaf: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}},
		hash:        "(don't overwrite the first or second one)",
	}
	c.cacheCertificate(ipCert)
	if cert, err := cfg.GetCertificate(helloNoSNI); err != nil {
		t.Errorf("Got an error with no SNI but matching IP, but shouldn't have: %v", err)
	} else if cert == nil || len(cert.Leaf.IPAddresses) == 0 {
		t.Errorf("Expected IP cert, got: %v", cert)
	}
}

// TestGetCertDuringHandshakeWaiterErrorPropagation verifies that when the
// "leader" goroutine loading/obtaining a certificate for a name fails (e.g.
// an on-demand permission denial), the failure is propagated directly to all
// goroutines waiting on it. Without propagation, each waiter recursively
// re-enters the wait queue and eventually performs its own load/obtain
// attempt; under sustained handshake load for uncertificated names those
// recursing goroutines accumulate without bound, each pinning live TLS
// handshake state.
func TestGetCertDuringHandshakeWaiterErrorPropagation(t *testing.T) {
	const serverName = "denied.example.com"

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}

	denyErr := errors.New("on-demand permission denied")
	release := make(chan struct{})
	var decisionCalls atomic.Int32
	cfg := &Config{
		Logger:    defaultTestLogger,
		certCache: c,
		OnDemand: &OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				decisionCalls.Add(1)
				<-release // hold the leader so waiters queue behind it
				return denyErr
			},
		},
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to create test connection: %v", err)
	}
	defer conn.Close()

	hello := &tls.ClientHelloInfo{ServerName: serverName, Conn: conn}
	ctx := context.Background()

	const numHandshakes = 5
	results := make(chan error, numHandshakes)

	// leader: takes the load slot for serverName and blocks in DecisionFunc
	go func() {
		_, err := cfg.getCertDuringHandshake(ctx, hello, true)
		results <- err
	}()

	// wait until the leader has registered itself in the wait queue
	for {
		certLoadWaitChansMu.Lock()
		_, registered := certLoadWaitChans[serverName]
		certLoadWaitChansMu.Unlock()
		if registered {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// waiters: queue behind the leader
	for i := 1; i < numHandshakes; i++ {
		go func() {
			_, err := cfg.getCertDuringHandshake(ctx, hello, true)
			results <- err
		}()
	}

	// Wait until every handshake goroutine is PARKED — the waiters blocked
	// in the wait-queue select and the leader blocked on the release
	// channel in DecisionFunc — before releasing the leader. Merely being
	// inside getCertDuringHandshake isn't enough: a goroutine still in the
	// preamble would miss the wait queue once the leader's cleanup runs
	// and become a second leader.
	parked := func() (selecting, receiving int) {
		buf := make([]byte, 1<<20)
		stacks := string(buf[:runtime.Stack(buf, true)])
		for _, g := range strings.Split(stacks, "\n\n") {
			if !strings.Contains(g, ").getCertDuringHandshake(") {
				continue
			}
			if strings.Contains(g, "[select]") {
				selecting++
			} else if strings.Contains(g, "[chan receive]") {
				receiving++
			}
		}
		return
	}
	for {
		selecting, receiving := parked()
		if selecting >= numHandshakes-1 && receiving >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release) // leader now fails with denyErr

	for i := 0; i < numHandshakes; i++ {
		if err := <-results; err == nil || !strings.Contains(err.Error(), denyErr.Error()) {
			t.Errorf("expected deny error, got: %v", err)
		}
	}

	// The decision func must have been called exactly once: only the leader
	// reaches the permission check; waiters receive its propagated error
	// rather than recursing into their own load/obtain attempts.
	if got := decisionCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 decision-func call (leader only), got %d", got)
	}
}

// TestHandshakeMaintenanceExpiredOCSPStaple verifies the three-state handling
// of an OCSP response during a handshake: a response past the midpoint of its
// validity period but not yet expired stays stapled while being refreshed,
// whereas an expired response is unstapled even when the refresh fails.
func TestHandshakeMaintenanceExpiredOCSPStaple(t *testing.T) {
	ctx := context.Background()

	// Point OCSP requests at a closed listener so refreshes fail deterministically.
	deadResponder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setting up dead responder address: %v", err)
	}
	deadURL := "http://" + deadResponder.Addr().String()
	deadResponder.Close()

	now := time.Now()
	issuerCert, issuerKey, _ := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             now.Add(-60 * 24 * time.Hour),
		NotAfter:              now.Add(60 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)

	leafCert, leafKey, leafPEM := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "staple.example"},
		DNSNames:     []string{"staple.example"},
		NotBefore:    now.Add(-30 * 24 * time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		OCSPServer:   []string{deadURL},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, issuerCert, issuerKey)

	keyPEM, err := PEMEncodePrivateKey(leafKey)
	if err != nil {
		t.Fatalf("encoding private key: %v", err)
	}

	// helper that builds a fresh cache/config/cert for each subtest
	setup := func(t *testing.T, resp *ocsp.Response, rawStaple []byte) (*Config, Certificate) {
		cache := &Cache{
			cache:      make(map[string]Certificate),
			cacheIndex: make(map[string][]string),
			logger:     defaultTestLogger,
		}
		cfg := &Config{
			Logger:    defaultTestLogger,
			certCache: cache,
			Storage:   &FileStorage{Path: t.TempDir()},
			OCSP: OCSPConfig{
				ResponderOverrides: map[string]string{deadURL: deadURL},
			},
		}
		cert, err := makeCertificate(leafPEM, keyPEM)
		if err != nil {
			t.Fatalf("making certificate: %v", err)
		}
		cert.managed = true
		cert.ocsp = resp
		cert.Certificate.OCSPStaple = rawStaple
		cache.cacheCertificate(cert)
		return cfg, cert
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setting up test connection: %v", err)
	}
	defer l.Close()
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dialing test connection: %v", err)
	}
	defer conn.Close()
	hello := &tls.ClientHelloInfo{ServerName: "staple.example", Conn: conn}

	makeResponse := func(thisUpdate, nextUpdate time.Time) (*ocsp.Response, []byte) {
		parsed := &ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: leafCert.SerialNumber,
			ThisUpdate:   thisUpdate,
			NextUpdate:   nextUpdate,
		}
		raw, err := ocsp.CreateResponse(issuerCert, issuerCert, *parsed, issuerKey.(crypto.Signer))
		if err != nil {
			t.Fatalf("creating OCSP response: %v", err)
		}
		return parsed, raw
	}

	t.Run("expired response is unstapled when refresh fails", func(t *testing.T) {
		resp, raw := makeResponse(now.Add(-10*time.Hour), now.Add(-time.Hour))
		cfg, cert := setup(t, resp, raw)

		maintained, err := cfg.handshakeMaintenance(ctx, hello, cert)
		if err != nil {
			t.Fatalf("handshakeMaintenance returned error: %v", err)
		}
		if maintained.Certificate.OCSPStaple != nil {
			t.Error("expired OCSP response must not remain stapled after a failed refresh")
		}

		cfg.certCache.mu.RLock()
		cached := cfg.certCache.cache[cert.hash]
		cfg.certCache.mu.RUnlock()
		if cached.Certificate.OCSPStaple != nil {
			t.Error("expired OCSP response must be cleared from the cache as well")
		}
	})

	t.Run("stale but valid response stays stapled when refresh fails", func(t *testing.T) {
		// Midpoint is now; NextUpdate is an hour out, so the response is due
		// for a refresh but still legally valid.
		resp, raw := makeResponse(now.Add(-2*time.Hour), now.Add(2*time.Hour))
		cfg, cert := setup(t, resp, raw)

		maintained, err := cfg.handshakeMaintenance(ctx, hello, cert)
		if err != nil {
			t.Fatalf("handshakeMaintenance returned error: %v", err)
		}
		if maintained.Certificate.OCSPStaple == nil {
			t.Error("a still-valid OCSP response should remain stapled while a refresh is attempted")
		}

		cfg.certCache.mu.RLock()
		cached := cfg.certCache.cache[cert.hash]
		cfg.certCache.mu.RUnlock()
		if cached.Certificate.OCSPStaple == nil {
			t.Error("a still-valid OCSP response should remain in the cache while a refresh is attempted")
		}
	})
}
