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
	"fmt"
	weakrand "math/rand/v2"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Cache is a structure that stores certificates in memory.
// A Cache indexes certificates by name for quick access
// during TLS handshakes, and avoids duplicating certificates
// in memory. Generally, there should only be one per process.
// However, that is not a strict requirement; but using more
// than one is a code smell, and may indicate an
// over-engineered design.
//
// An empty cache is INVALID and must not be used. Be sure
// to call NewCache to get a valid value.
//
// These should be very long-lived values and must not be
// copied. Before all references leave scope to be garbage
// collected, ensure you call Stop() to stop maintenance on
// the certificates stored in this cache and release locks.
//
// Caches are not usually manipulated directly; create a
// Config value with a pointer to a Cache, and then use
// the Config to interact with the cache. Caches are
// agnostic of any particular storage or ACME config,
// since each certificate may be managed and stored
// differently.
type Cache struct {
	// User configuration of the cache
	options   CacheOptions
	optionsMu sync.RWMutex

	// The cache is keyed by certificate hash
	cache map[string]Certificate

	// cacheIndex is a map of SAN to cache key (cert hash)
	cacheIndex map[string][]string

	// managedCerts is an index of managed certificates by hash. Unlike
	// cache, entries are kept when a managed certificate is evicted for
	// capacity reasons, so maintenance can find it again in storage.
	managedCerts map[string]managedCertRef

	// managedNames maps a SAN to the hashes in managedCerts. It is kept
	// in sync with managedCerts so handshakes can tell whether a cache
	// miss is for a managed certificate that was evicted.
	managedNames map[string]map[string]struct{}

	// removedManaged records managed names that were explicitly removed,
	// mapping each name to the issuers it was removed from. Maintenance
	// consults it so its storage scan doesn't revive removed certificates.
	removedManaged map[string]map[string]struct{}

	// Protects the cache, cacheIndex, managedCerts, managedNames, and
	// removedManaged maps
	mu sync.RWMutex

	// Close this channel to cancel asset maintenance
	stopChan chan struct{}

	// Used to signal when stopping is completed
	doneChan chan struct{}

	logger *zap.Logger
}

// managedCertRef is the small amount of metadata needed
// to find an evicted managed certificate in storage again.
type managedCertRef struct {
	names     []string
	issuerKey string
}

// NewCache returns a new, valid Cache for efficiently
// accessing certificates in memory. It also begins a
// maintenance goroutine to tend to the certificates
// in the cache. Call Stop() when you are done with the
// cache so it can clean up locks and stuff.
//
// Most users of this package will not need to call this
// because a default certificate cache is created for you.
// Only advanced use cases require creating a new cache.
//
// This function panics if opts.GetConfigForCert is not
// set. The reason is that a cache absolutely needs to
// be able to get a Config with which to manage TLS
// assets, and it is not safe to assume that the Default
// config is always the correct one, since you have
// created the cache yourself.
//
// See the godoc for Cache to use it properly. When
// no longer needed, caches should be stopped with
// Stop() to clean up resources even if the process
// is being terminated, so that it can clean up
// any locks for other processes to unblock!
func NewCache(opts CacheOptions) *Cache {
	c := &Cache{
		cache:          make(map[string]Certificate),
		cacheIndex:     make(map[string][]string),
		managedCerts:   make(map[string]managedCertRef),
		managedNames:   make(map[string]map[string]struct{}),
		removedManaged: make(map[string]map[string]struct{}),
		stopChan:       make(chan struct{}),
		doneChan:       make(chan struct{}),
		logger:         opts.Logger,
	}

	// absolutely do not allow a nil logger; panics galore
	if c.logger == nil {
		c.logger = defaultLogger
	}

	c.SetOptions(opts)

	go c.maintainAssets(0)

	return c
}

func (certCache *Cache) SetOptions(opts CacheOptions) {
	// assume default options if necessary
	if opts.OCSPCheckInterval <= 0 {
		opts.OCSPCheckInterval = DefaultOCSPCheckInterval
	}
	if opts.RenewCheckInterval <= 0 {
		opts.RenewCheckInterval = DefaultRenewCheckInterval
	}
	if opts.Capacity < 0 {
		opts.Capacity = 0
	}

	// this must be set, because we cannot not
	// safely assume that the Default Config
	// is always the correct one to use
	if opts.GetConfigForCert == nil {
		panic("cache must be initialized with a GetConfigForCert callback")
	}

	certCache.optionsMu.Lock()
	certCache.options = opts
	certCache.optionsMu.Unlock()
}

// Stop stops the maintenance goroutine for
// certificates in certCache. It blocks until
// stopping is complete. Once a cache is
// stopped, it cannot be reused.
func (certCache *Cache) Stop() {
	close(certCache.stopChan) // signal to stop
	<-certCache.doneChan      // wait for stop to complete
}

// CacheOptions is used to configure certificate caches.
// Once a cache has been created with certain options,
// those settings cannot be changed.
type CacheOptions struct {
	// REQUIRED. A function that returns a configuration
	// used for managing a certificate, or for accessing
	// that certificate's asset storage (e.g. for
	// OCSP staples, etc). The returned Config MUST
	// be associated with the same Cache as the caller,
	// use New to obtain a valid Config.
	//
	// The reason this is a callback function, dynamically
	// returning a Config (instead of attaching a static
	// pointer to a Config on each certificate) is because
	// the config for how to manage a domain's certificate
	// might change from maintenance to maintenance. The
	// cache is so long-lived, we cannot assume that the
	// host's situation will always be the same; e.g. the
	// certificate might switch DNS providers, so the DNS
	// challenge (if used) would need to be adjusted from
	// the last time it was run ~8 weeks ago.
	GetConfigForCert ConfigGetter

	// How often to check certificates for renewal;
	// if unset, DefaultOCSPCheckInterval will be used.
	OCSPCheckInterval time.Duration

	// How often to check certificates for renewal;
	// if unset, DefaultRenewCheckInterval will be used.
	RenewCheckInterval time.Duration

	// Maximum number of certificates to allow in the cache.
	// If reached, certificates will be evicted to make room for
	// new ones. Managed certificates are preferred for eviction
	// because they can be loaded again from storage; they remain
	// in the managed index so maintenance can still renew them.
	// 0 means unlimited.
	Capacity int

	// Set a logger to enable logging
	Logger *zap.Logger
}

// ConfigGetter is a function that returns a prepared,
// valid config that should be used when managing the
// given certificate or its assets.
type ConfigGetter func(Certificate) (*Config, error)

// cacheCertificate calls unsyncedCacheCertificate with a write lock.
//
// This function is safe for concurrent use.
func (certCache *Cache) cacheCertificate(cert Certificate) {
	certCache.mu.Lock()
	certCache.unsyncedCacheCertificate(cert)
	certCache.mu.Unlock()
}

// unsyncedCacheCertificate adds cert to the in-memory cache unless
// it already exists in the cache (according to cert.Hash). It
// updates the name index.
//
// This function is NOT safe for concurrent use. Callers MUST acquire
// a write lock on certCache.mu first.
func (certCache *Cache) unsyncedCacheCertificate(cert Certificate) {
	// if this certificate already exists in the cache, this is basically
	// a no-op so we reuse existing cert (prevent duplication), but we do
	// modify the cert to add tags it may be missing (see issue #211)
	if existingCert, ok := certCache.cache[cert.hash]; ok {
		certCache.trackManagedCertificateLocked(existingCert)
		logMsg := "certificate already cached"

		if len(cert.Tags) > 0 {
			for _, tag := range cert.Tags {
				if !existingCert.HasTag(tag) {
					existingCert.Tags = append(existingCert.Tags, tag)
				}
			}
			certCache.cache[cert.hash] = existingCert
			logMsg += "; appended any missing tags to cert"
		}

		certCache.logger.Debug(logMsg,
			zap.Strings("subjects", cert.Names),
			zap.Time("expiration", expiresAt(cert.Leaf)),
			zap.Bool("managed", cert.managed),
			zap.String("issuer_key", cert.issuerKey),
			zap.String("hash", cert.hash),
			zap.Strings("tags", cert.Tags))
		return
	}

	// if the cache is at capacity, make room for new cert
	cacheSize := len(certCache.cache)
	certCache.optionsMu.RLock()
	atCapacity := certCache.options.Capacity > 0 && cacheSize >= certCache.options.Capacity
	certCache.optionsMu.RUnlock()

	if atCapacity {
		certCache.evictCertificateLocked(cert)
	}

	// store the certificate
	certCache.cache[cert.hash] = cert

	// update the index so we can access it by name
	for _, name := range cert.Names {
		certCache.cacheIndex[name] = append(certCache.cacheIndex[name], cert.hash)
	}

	if cert.managed {
		certCache.clearRemovedManagedLocked(cert)
	}
	certCache.trackManagedCertificateLocked(cert)

	certCache.optionsMu.RLock()
	certCache.logger.Debug("added certificate to cache",
		zap.Strings("subjects", cert.Names),
		zap.Time("expiration", expiresAt(cert.Leaf)),
		zap.Bool("managed", cert.managed),
		zap.String("issuer_key", cert.issuerKey),
		zap.String("hash", cert.hash),
		zap.Int("cache_size", len(certCache.cache)),
		zap.Int("cache_capacity", certCache.options.Capacity))
	certCache.optionsMu.RUnlock()
}

// evictCertificateLocked makes room for inserting by evicting one
// certificate. Managed certificates are preferred because they can be
// loaded again from storage; manually-loaded certificates have no other
// source. If only manually-loaded certificates are present, one of them
// is still evicted, otherwise the cache would grow without bound.
//
// This function is NOT safe for concurrent use. Callers MUST first
// acquire a write lock on certCache.mu.
func (certCache *Cache) evictCertificateLocked(inserting Certificate) {
	keys := make([]string, 0, len(certCache.cache))
	for key := range certCache.cache {
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return
	}

	// Go maps are "nondeterministic" but not actually random, so start
	// at a random offset to get a better distribution of evictions.
	offset := weakrand.IntN(len(keys))

	var evicted Certificate
	var fallback Certificate
	var haveEvicted, haveFallback bool
	for i := range keys {
		candidate := certCache.cache[keys[(offset+i)%len(keys)]]
		if candidate.managed {
			evicted = candidate
			haveEvicted = true
			break
		}
		if !haveFallback {
			fallback = candidate
			haveFallback = true
		}
	}
	if !haveEvicted && haveFallback {
		evicted = fallback
		haveEvicted = true
	}
	if !haveEvicted {
		return
	}

	certCache.logger.Debug("cache full; evicting certificate",
		zap.Strings("removing_subjects", evicted.Names),
		zap.Bool("removing_managed", evicted.managed),
		zap.String("removing_hash", evicted.hash),
		zap.Strings("inserting_subjects", inserting.Names),
		zap.String("inserting_hash", inserting.hash))
	certCache.removeCertificate(evicted)
}

// trackManagedCertificateLocked records a managed certificate in the
// managed index. The entry intentionally survives capacity eviction.
//
// This function is NOT safe for concurrent use. Callers MUST first
// acquire a write lock on certCache.mu.
func (certCache *Cache) trackManagedCertificateLocked(cert Certificate) {
	if !cert.managed || cert.hash == "" {
		return
	}
	if certCache.managedCerts == nil {
		certCache.managedCerts = make(map[string]managedCertRef)
	}
	if certCache.managedNames == nil {
		certCache.managedNames = make(map[string]map[string]struct{})
	}

	ref := managedCertRef{
		names:     append([]string(nil), cert.Names...),
		issuerKey: cert.issuerKey,
	}
	certCache.managedCerts[cert.hash] = ref
	for _, name := range ref.names {
		hashes := certCache.managedNames[name]
		if hashes == nil {
			hashes = make(map[string]struct{})
			certCache.managedNames[name] = hashes
		}
		hashes[cert.hash] = struct{}{}
	}
}

// untrackManagedCertificateLocked removes hash from the managed index.
//
// This function is NOT safe for concurrent use. Callers MUST first
// acquire a write lock on certCache.mu.
func (certCache *Cache) untrackManagedCertificateLocked(hash string) {
	ref, ok := certCache.managedCerts[hash]
	if !ok {
		return
	}
	for _, name := range ref.names {
		hashes := certCache.managedNames[name]
		delete(hashes, hash)
		if len(hashes) == 0 {
			delete(certCache.managedNames, name)
		}
	}
	delete(certCache.managedCerts, hash)
}

// untrackManagedCertificate removes hash from the managed index.
func (certCache *Cache) untrackManagedCertificate(hash string) {
	certCache.mu.Lock()
	certCache.untrackManagedCertificateLocked(hash)
	certCache.mu.Unlock()
}

// trackManagedCertificate adds cert to the managed index.
func (certCache *Cache) trackManagedCertificate(cert Certificate) {
	certCache.mu.Lock()
	certCache.trackManagedCertificateLocked(cert)
	certCache.mu.Unlock()
}

// markManagedRemovedLocked remembers that cert was explicitly removed,
// so maintenance does not load it back from storage.
func (certCache *Cache) markManagedRemovedLocked(cert Certificate) {
	if !cert.managed {
		return
	}
	if certCache.removedManaged == nil {
		certCache.removedManaged = make(map[string]map[string]struct{})
	}
	for _, name := range cert.Names {
		issuers := certCache.removedManaged[name]
		if issuers == nil {
			issuers = make(map[string]struct{})
			certCache.removedManaged[name] = issuers
		}
		issuers[cert.issuerKey] = struct{}{}
	}
}

// clearRemovedManagedLocked forgets any explicit removal of cert, which
// is what happens when a subject is managed again.
func (certCache *Cache) clearRemovedManagedLocked(cert Certificate) {
	for _, name := range cert.Names {
		issuers := certCache.removedManaged[name]
		delete(issuers, cert.issuerKey)
		if len(issuers) == 0 {
			delete(certCache.removedManaged, name)
		}
	}
}

// isManagedRemoved reports whether cert was explicitly removed from
// management and should not be revived by maintenance.
func (certCache *Cache) isManagedRemoved(cert Certificate) bool {
	certCache.mu.RLock()
	defer certCache.mu.RUnlock()
	for _, name := range cert.Names {
		if _, ok := certCache.removedManaged[name][cert.issuerKey]; ok {
			return true
		}
	}
	return false
}

// managedCertRefs returns a snapshot of managed certificates that are
// not currently in the in-memory cache.
func (certCache *Cache) managedCertRefs() []Certificate {
	certCache.mu.RLock()
	defer certCache.mu.RUnlock()

	certs := make([]Certificate, 0, len(certCache.managedCerts))
	for hash, ref := range certCache.managedCerts {
		if _, ok := certCache.cache[hash]; ok {
			continue
		}
		certs = append(certs, Certificate{
			Names:     append([]string(nil), ref.names...),
			hash:      hash,
			managed:   true,
			issuerKey: ref.issuerKey,
		})
	}
	return certs
}

// hasManagedCertificateNamed reports whether name is served by a managed
// certificate known to this cache, even if that certificate is not in
// memory right now. Wildcards are considered.
func (certCache *Cache) hasManagedCertificateNamed(name string) bool {
	name = normalizedName(name)
	if name == "" {
		return false
	}

	certCache.mu.RLock()
	defer certCache.mu.RUnlock()

	if len(certCache.managedNames[name]) > 0 {
		return true
	}
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		if len(certCache.managedNames[strings.Join(labels, ".")]) > 0 {
			return true
		}
	}
	return false
}

// removeCertificate removes cert from the cache.
//
// This function is NOT safe for concurrent use; callers
// MUST first acquire a write lock on certCache.mu.
func (certCache *Cache) removeCertificate(cert Certificate) {
	// delete all mentions of this cert from the name index
	for _, name := range cert.Names {
		keyList := certCache.cacheIndex[name]
		for i := 0; i < len(keyList); i++ {
			if keyList[i] == cert.hash {
				keyList = append(keyList[:i], keyList[i+1:]...)
				i--
			}
		}
		if len(keyList) == 0 {
			delete(certCache.cacheIndex, name)
		} else {
			certCache.cacheIndex[name] = keyList
		}
	}

	// delete the actual cert from the cache
	delete(certCache.cache, cert.hash)

	certCache.optionsMu.RLock()
	certCache.logger.Debug("removed certificate from cache",
		zap.Strings("subjects", cert.Names),
		zap.Time("expiration", expiresAt(cert.Leaf)),
		zap.Bool("managed", cert.managed),
		zap.String("issuer_key", cert.issuerKey),
		zap.String("hash", cert.hash),
		zap.Int("cache_size", len(certCache.cache)),
		zap.Int("cache_capacity", certCache.options.Capacity))
	certCache.optionsMu.RUnlock()
}

// replaceCertificate atomically replaces oldCert with newCert in
// the cache.
//
// This method is safe for concurrent use.
func (certCache *Cache) replaceCertificate(oldCert, newCert Certificate) {
	certCache.mu.Lock()
	certCache.removeCertificate(oldCert)
	certCache.untrackManagedCertificateLocked(oldCert.hash)
	certCache.unsyncedCacheCertificate(newCert)
	certCache.mu.Unlock()
	certCache.logger.Info("replaced certificate in cache",
		zap.Strings("subjects", newCert.Names),
		zap.Time("new_expiration", expiresAt(newCert.Leaf)))
}

// getAllMatchingCerts returns all certificates with exactly this subject
// (wildcards are NOT expanded).
func (certCache *Cache) getAllMatchingCerts(subject string) []Certificate {
	certCache.mu.RLock()
	defer certCache.mu.RUnlock()

	allCertKeys := certCache.cacheIndex[subject]

	certs := make([]Certificate, len(allCertKeys))
	for i := range allCertKeys {
		certs[i] = certCache.cache[allCertKeys[i]]
	}

	return certs
}

func (certCache *Cache) getAllCerts() []Certificate {
	certCache.mu.RLock()
	defer certCache.mu.RUnlock()
	certs := make([]Certificate, 0, len(certCache.cache))
	for _, cert := range certCache.cache {
		certs = append(certs, cert)
	}
	return certs
}

func (certCache *Cache) getConfig(cert Certificate) (*Config, error) {
	certCache.optionsMu.RLock()
	getCert := certCache.options.GetConfigForCert
	certCache.optionsMu.RUnlock()

	cfg, err := getCert(cert)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		// this is bad if this happens, probably a programmer error (oops)
		return nil, fmt.Errorf("no configuration associated with certificate: %v;", cert.Names)
	}
	if cfg.certCache == nil {
		return nil, fmt.Errorf("config returned for certificate %v has nil cache; expected %p (this one)",
			cert.Names, certCache)
	}
	if cfg.certCache != certCache {
		return nil, fmt.Errorf("config returned for certificate %v is not nil and points to different cache; got %p, expected %p (this one)",
			cert.Names, cfg.certCache, certCache)
	}
	return cfg, nil
}

// AllMatchingCertificates returns a list of all certificates that could
// be used to serve the given SNI name, including exact SAN matches and
// wildcard matches.
func (certCache *Cache) AllMatchingCertificates(name string) []Certificate {
	// get exact matches first
	certs := certCache.getAllMatchingCerts(name)

	// then look for wildcard matches by replacing each
	// label of the domain name with wildcards
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		certs = append(certs, certCache.getAllMatchingCerts(candidate)...)
	}

	return certs
}

// SubjectIssuer pairs a subject name with an issuer ID/key.
type SubjectIssuer struct {
	Subject, IssuerKey string
}

// RemoveManaged removes managed certificates for the given subjects from the cache.
// This effectively stops maintenance of those certificates. If an IssuerKey is
// specified alongside the subject, only certificates for that subject from the
// specified issuer will be removed.
func (certCache *Cache) RemoveManaged(subjects []SubjectIssuer) {
	deleteQueue := make([]string, 0, len(subjects))
	for _, subj := range subjects {
		certs := certCache.getAllMatchingCerts(subj.Subject) // does NOT expand wildcards; exact matches only
		for _, cert := range certs {
			if !cert.managed {
				continue
			}
			if subj.IssuerKey == "" || cert.issuerKey == subj.IssuerKey {
				deleteQueue = append(deleteQueue, cert.hash)
			}
		}
	}

	// Evicted managed certificates are not in cache anymore, but they
	// are still in the managed index, so remove those too.
	certCache.mu.RLock()
	for _, subj := range subjects {
		for hash, ref := range certCache.managedCerts {
			for _, name := range ref.names {
				if name != subj.Subject {
					continue
				}
				if subj.IssuerKey == "" || ref.issuerKey == subj.IssuerKey {
					deleteQueue = append(deleteQueue, hash)
				}
				break
			}
		}
	}
	certCache.mu.RUnlock()

	certCache.Remove(deleteQueue)
}

// Remove removes certificates with the given hashes from the cache.
// This is effectively used to unload manually-loaded certificates.
func (certCache *Cache) Remove(hashes []string) {
	certCache.mu.Lock()
	for _, h := range hashes {
		cert := certCache.cache[h]
		if cert.hash == "" {
			if ref, ok := certCache.managedCerts[h]; ok {
				cert = Certificate{
					Names:     append([]string(nil), ref.names...),
					hash:      h,
					managed:   true,
					issuerKey: ref.issuerKey,
				}
			}
		}
		certCache.removeCertificate(cert)
		certCache.markManagedRemovedLocked(cert)
		certCache.untrackManagedCertificateLocked(h)
	}
	certCache.mu.Unlock()
}

var (
	defaultCache   *Cache
	defaultCacheMu sync.Mutex
)
