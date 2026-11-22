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
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	noop := func(Certificate) (*Config, error) { return new(Config), nil }
	c := NewCache(CacheOptions{GetConfigForCert: noop})
	defer c.Stop()

	c.optionsMu.RLock()
	defer c.optionsMu.RUnlock()

	if c.options.RenewCheckInterval != DefaultRenewCheckInterval {
		t.Errorf("Expected RenewCheckInterval to be set to default value, but it wasn't: %s", c.options.RenewCheckInterval)
	}
	if c.options.OCSPCheckInterval != DefaultOCSPCheckInterval {
		t.Errorf("Expected OCSPCheckInterval to be set to default value, but it wasn't: %s", c.options.OCSPCheckInterval)
	}
	if c.options.GetConfigForCert == nil {
		t.Error("Expected GetConfigForCert to be set, but it was nil")
	}
	if c.cache == nil {
		t.Error("Expected cache to be set, but it was nil")
	}
	if c.stopChan == nil {
		t.Error("Expected stopChan to be set, but it was nil")
	}
}

func TestCacheEvictionKeepsManagedIndex(t *testing.T) {
	noop := func(Certificate) (*Config, error) { return new(Config), nil }
	c := NewCache(CacheOptions{
		GetConfigForCert: noop,
		Capacity:         2,
		Logger:           defaultTestLogger,
	})
	defer c.Stop()

	newCert := func(name, hash string, managed bool) Certificate {
		return Certificate{
			Names:   []string{name},
			hash:    hash,
			managed: managed,
			Certificate: tls.Certificate{Leaf: &x509.Certificate{
				NotAfter: time.Now().Add(24 * time.Hour),
			}},
		}
	}

	// A manually-loaded certificate has no other source, so a managed
	// certificate should be evicted first when the cache fills up.
	manual := newCert("manual.example", "manual", false)
	firstManaged := newCert("first.example", "first-managed", true)
	secondManaged := newCert("second.example", "second-managed", true)
	c.cacheCertificate(manual)
	c.cacheCertificate(firstManaged)
	c.cacheCertificate(secondManaged)

	if len(c.cache) != 2 {
		t.Fatalf("expected cache size 2, got %d", len(c.cache))
	}
	if _, ok := c.cache[manual.hash]; !ok {
		t.Error("expected manually-loaded certificate to remain cached")
	}
	if _, ok := c.cache[firstManaged.hash]; ok {
		t.Error("expected managed certificate to be evicted")
	}
	if !c.hasManagedCertificateNamed("first.example") {
		t.Error("expected evicted managed certificate to remain in the managed index")
	}
	if refs := c.managedCertRefs(); len(refs) != 1 || refs[0].hash != firstManaged.hash {
		t.Fatalf("expected one evicted managed certificate in the index, got %v", refs)
	}
}
