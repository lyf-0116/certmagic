// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrNoOCSPServerSpecified indicates that OCSP information could not be
// stapled because the certificate does not support OCSP.
var ErrNoOCSPServerSpecified = errors.New("no OCSP server specified in certificate")

// ErrOCSPBackoff indicates that an OCSP fetch was not even attempted
// because the responder recently failed and the bounded negative cache
// ("backoff") for this certificate is still in effect.
var ErrOCSPBackoff = errors.New("OCSP responder recently failed; backing off")

// stapleStatus classifies the state of a certificate's OCSP staple.
// Every certificate carries one so that handshake, maintenance, and
// reload paths can make serving decisions without re-fetching.
type stapleStatus int

const (
	// stapleStatusNone means no stapling has been attempted or no
	// information is available.
	stapleStatusNone stapleStatus = iota
	// stapleStatusGood means a Good OCSP response is stapled.
	stapleStatusGood
	// stapleStatusRevoked means the responder reported the certificate
	// as revoked.
	stapleStatusRevoked
	// stapleStatusUnknown means the responder answered, but with a
	// status that is neither Good nor Revoked.
	stapleStatusUnknown
	// stapleStatusFailedTransient means the last fetch failed in a way
	// that may succeed if retried later (responder or network trouble).
	// A bounded negative cache applies before the next attempt.
	stapleStatusFailedTransient
	// stapleStatusFailedPermanent means the last fetch failed in a way
	// that retrying cannot fix (e.g. the certificate names no OCSP
	// server).
	stapleStatusFailedPermanent
)

// String returns a short human-readable label for the staple status.
func (s stapleStatus) String() string {
	switch s {
	case stapleStatusGood:
		return "good"
	case stapleStatusRevoked:
		return "revoked"
	case stapleStatusUnknown:
		return "unknown"
	case stapleStatusFailedTransient:
		return "transient_failure"
	case stapleStatusFailedPermanent:
		return "permanent_failure"
	default:
		return "none"
	}
}

// Bounds for the negative cache applied to transient OCSP failures:
// retries back off exponentially from ocspBackoffBase, never exceeding
// ocspBackoffMax, and the failure counter is capped so the schedule
// stays bounded no matter how long the responder is down.
const (
	ocspBackoffBase        = time.Minute
	ocspBackoffMax         = time.Hour
	ocspBackoffMaxAttempts = 8
)

// recordStapleFailure notes a transient OCSP fetch failure on cert and
// sets the time before which no further fetch should be attempted.
func (cert *Certificate) recordStapleFailure(now time.Time) {
	if cert.stapleAttempts < ocspBackoffMaxAttempts {
		cert.stapleAttempts++
	}
	delay := ocspBackoffBase << (cert.stapleAttempts - 1)
	if delay > ocspBackoffMax {
		delay = ocspBackoffMax
	}
	cert.stapleRetryAt = now.Add(delay)
}

// resetStapleBackoff clears the negative cache for cert, e.g. after a
// successful response from the OCSP responder.
func (cert *Certificate) resetStapleBackoff() {
	cert.stapleAttempts = 0
	cert.stapleRetryAt = time.Time{}
}

// hasMustStaple returns true if the certificate carries the must-staple
// (status_request) TLS feature extension, RFC 7633.
func hasMustStaple(leaf *x509.Certificate) bool {
	if leaf == nil {
		return false
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(tlsFeatureExtensionOID) {
			continue
		}
		var features []int
		if _, err := asn1.Unmarshal(ext.Value, &features); err != nil {
			continue
		}
		for _, feature := range features {
			if feature == 5 { // status_request
				return true
			}
		}
	}
	return false
}

// stapleOCSP staples OCSP information to cert for hostname name.
// If you have it handy, you should pass in the PEM-encoded certificate
// bundle; otherwise the DER-encoded cert will have to be PEM-encoded.
// If you don't have the PEM blocks already, just pass in nil.
//
// If successful, the OCSP response will be set to cert's ocsp field,
// regardless of the OCSP status. It is only stapled, however, if the
// status is Good.
//
// Errors here are not necessarily fatal, it could just be that the
// certificate doesn't have an issuer URL.
func stapleOCSP(ctx context.Context, ocspConfig OCSPConfig, storage Storage, cert *Certificate, pemBundle []byte) error {
	if ocspConfig.DisableStapling {
		return nil
	}

	if pemBundle == nil {
		// we need a PEM encoding only for some function calls below
		bundle := new(bytes.Buffer)
		for _, derBytes := range cert.Certificate.Certificate {
			_ = pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		}
		pemBundle = bundle.Bytes()
	}

	var ocspBytes []byte
	var ocspResp *ocsp.Response
	var ocspErr error
	var gotNewOCSP bool

	// First try to load OCSP staple from storage and see if
	// we can still use it.
	ocspStapleKey := StorageKeys.OCSPStaple(cert, pemBundle)
	cachedOCSP, err := storage.Load(ctx, ocspStapleKey)
	if err == nil {
		resp, err := ocsp.ParseResponse(cachedOCSP, nil)
		if err == nil {
			if freshOCSP(resp) {
				// staple is still fresh; use it
				ocspBytes = cachedOCSP
				ocspResp = resp
			}
		} else {
			// invalid contents; delete the file
			// (we do this independently of the maintenance routine because
			// in this case we know for sure this should be a staple file
			// because we loaded it by name, whereas the maintenance routine
			// just iterates the list of files, even if somehow a non-staple
			// file gets in the folder. in this case we are sure it is corrupt.)
			err := storage.Delete(ctx, ocspStapleKey)
			if err != nil {
				log.Printf("[WARNING] Unable to delete invalid OCSP staple file: %v", err)
			}
		}
	}

	// If we couldn't get a fresh staple by reading the cache,
	// then we need to request it from the OCSP responder
	if ocspResp == nil || len(ocspBytes) == 0 {
		// Negative cache: if the responder recently failed, don't pound
		// it on every handshake or maintenance run; wait out the bounded
		// backoff instead.
		if time.Now().Before(cert.stapleRetryAt) {
			return fmt.Errorf("%w for %v (retry after %s)",
				ErrOCSPBackoff, cert.Names, cert.stapleRetryAt.Format(time.RFC3339))
		}
		ocspBytes, ocspResp, ocspErr = getOCSPForCert(ocspConfig, pemBundle)
		// An error here is not a problem because a certificate
		// may simply not contain a link to an OCSP server.
		if ocspErr != nil {
			// Classify the failure: permanent problems (like a certificate
			// that names no OCSP server) can never be fixed by retrying,
			// whereas transient ones (responder or network trouble) get a
			// bounded negative cache so that we neither hammer the
			// responder nor take must-staple sites down during an outage.
			if errors.Is(ocspErr, ErrNoOCSPServerSpecified) {
				cert.stapleStatus = stapleStatusFailedPermanent
				cert.resetStapleBackoff()
			} else {
				cert.stapleStatus = stapleStatusFailedTransient
				cert.recordStapleFailure(time.Now())
			}
			// For short-lived certificates, this is fine and we can ignore
			// logging because OCSP doesn't make much sense for them anyway.
			if cert.Lifetime() < 7*24*time.Hour {
				return nil
			}
			// There's nothing else we can do to get OCSP for this certificate,
			// so we can return here with the error to warn about it.
			return fmt.Errorf("no OCSP stapling for %v: %w", cert.Names, ocspErr)
		}
		gotNewOCSP = true
	}

	if ocspResp.NextUpdate.After(expiresAt(cert.Leaf)) {
		// uh oh, this OCSP response expires AFTER the certificate does, that's kinda bogus.
		// it was the reason a lot of Symantec-validated sites (not Caddy) went down
		// in October 2017. https://twitter.com/mattiasgeniar/status/919432824708648961
		return fmt.Errorf("invalid: OCSP response for %v valid after certificate expiration (%s)",
			cert.Names, expiresAt(cert.Leaf).Sub(ocspResp.NextUpdate))
	}

	// Attach the latest OCSP response to the certificate; this is NOT the same
	// as stapling it, which we do below only if the status is Good, but it is
	// useful to keep with the cert in order to act on it later (like if Revoked).
	cert.ocsp = ocspResp

	// Record the staple status on the certificate so that the handshake,
	// maintenance, and reload paths can decide how to treat it. The
	// responder answered, so any negative-cache backoff is cleared.
	switch ocspResp.Status {
	case ocsp.Good:
		cert.stapleStatus = stapleStatusGood
	case ocsp.Revoked:
		cert.stapleStatus = stapleStatusRevoked
	default:
		cert.stapleStatus = stapleStatusUnknown
	}
	cert.resetStapleBackoff()

	// If the response is good, staple it to the certificate. If the OCSP
	// response was not loaded from storage, we persist it for next time.
	if ocspResp.Status == ocsp.Good {
		cert.Certificate.OCSPStaple = ocspBytes
		if gotNewOCSP {
			err := storage.Store(ctx, ocspStapleKey, ocspBytes)
			if err != nil {
				return fmt.Errorf("unable to write OCSP staple file for %v: %v", cert.Names, err)
			}
		}
	}

	return nil
}

// getOCSPForCert takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any. The returned []byte can be passed directly
// into the OCSPStaple property of a tls.Certificate. If the bundle only contains the
// issued certificate, this function will try to get the issuer certificate from the
// IssuingCertificateURL in the certificate. If the []byte and/or ocsp.Response return
// values are nil, the OCSP status may be assumed OCSPUnknown.
//
// Borrowed from xenolf.
func getOCSPForCert(ocspConfig OCSPConfig, bundle []byte) ([]byte, *ocsp.Response, error) {
	// TODO: Perhaps this should be synchronized too, with a Locker?

	certificates, err := parseCertsFromPEMBundle(bundle)
	if err != nil {
		return nil, nil, err
	}

	// We expect the certificate slice to be ordered downwards the chain.
	// SRV CRT -> CA. We need to pull the leaf and issuer certs out of it,
	// which should always be the first two certificates. If there's no
	// OCSP server listed in the leaf cert, there's nothing to do. And if
	// we have only one certificate so far, we need to get the issuer cert.
	issuedCert := certificates[0]
	if len(issuedCert.OCSPServer) == 0 {
		return nil, nil, ErrNoOCSPServerSpecified
	}

	// apply override for responder URL
	respURL := issuedCert.OCSPServer[0]
	if len(ocspConfig.ResponderOverrides) > 0 {
		if override, ok := ocspConfig.ResponderOverrides[respURL]; ok {
			respURL = override
		}
	}
	if respURL == "" {
		return nil, nil, fmt.Errorf("override disables querying OCSP responder: %v", issuedCert.OCSPServer[0])
	}

	// configure HTTP client if necessary
	httpClient := http.DefaultClient
	if ocspConfig.HTTPProxy != nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy: ocspConfig.HTTPProxy,
			},
			Timeout: 30 * time.Second,
		}
	}

	// get issuer certificate if needed
	if len(certificates) == 1 {
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, nil, fmt.Errorf("no URL to issuing certificate")
		}

		resp, err := httpClient.Get(issuedCert.IssuingCertificateURL[0])
		if err != nil {
			return nil, nil, fmt.Errorf("getting issuer certificate: %v", err)
		}
		defer resp.Body.Close()

		issuerBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return nil, nil, fmt.Errorf("reading issuer certificate: %v", err)
		}

		issuerCert, err := x509.ParseCertificate(issuerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing issuer certificate: %v", err)
		}

		// insert it into the slice on position 0;
		// we want it ordered right SRV CRT -> CA
		certificates = append(certificates, issuerCert)
	}

	issuerCert := certificates[1]

	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OCSP request: %v", err)
	}

	reader := bytes.NewReader(ocspReq)
	req, err := httpClient.Post(respURL, "application/ocsp-request", reader)
	if err != nil {
		return nil, nil, fmt.Errorf("making OCSP request: %v", err)
	}
	defer req.Body.Close()

	ocspResBytes, err := io.ReadAll(io.LimitReader(req.Body, 1024*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("reading OCSP response: %v", err)
	}

	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing OCSP response: %v", err)
	}

	if err := validateOCSPResponder(ocspRes, issuerCert); err != nil {
		return nil, nil, fmt.Errorf("OCSP responder authorization check failed: %v", err)
	}

	return ocspResBytes, ocspRes, nil
}

// freshOCSP returns true if resp is still fresh,
// meaning that it is not expedient to get an
// updated response from the OCSP server.
func freshOCSP(resp *ocsp.Response) bool {
	nextUpdate := resp.NextUpdate
	// If there is an OCSP responder certificate, and it expires before the
	// OCSP response, use its expiration date as the end of the OCSP
	// response's validity period.
	if resp.Certificate != nil && resp.Certificate.NotAfter.Before(nextUpdate) {
		nextUpdate = resp.Certificate.NotAfter
	}
	// start checking OCSP staple about halfway through validity period for good measure
	refreshTime := resp.ThisUpdate.Add(nextUpdate.Sub(resp.ThisUpdate) / 2)
	return time.Now().Before(refreshTime)
}

// validateOCSPResponder enforces RFC 6960 §4.2.2.2: "Systems or applications that
// rely on OCSP responses MUST be capable of detecting and enforcing the use of the
// id-kp-OCSPSigning value." An issuer-signed response (where the embedded Certificate
// field is nil, meaning the issuer signed directly) is always acceptable.
func validateOCSPResponder(ocspResp *ocsp.Response, issuerCert *x509.Certificate) error {
	respCert := ocspResp.Certificate

	// if response was signed directly by the issuer, or embedded responder cert IS the issuer, accept
	if respCert == nil || respCert.Equal(issuerCert) {
		// Response was signed directly by the issuer — always valid.
		return nil
	}

	// RFC 6960 §4.2.2.2 requires id-kp-OCSPSigning for delegated responders
	for _, eku := range respCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			return nil
		}
	}

	return fmt.Errorf("OCSP responder certificate (subject: %s) is not the issuer and does not carry id-kp-OCSPSigning", respCert.Subject)
}
