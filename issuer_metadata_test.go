package certmagic

import (
	"context"
	"crypto/x509"
	"errors"
	"io/fs"
	"testing"

	"go.uber.org/zap"
)

type metadataFakeIssuer struct {
	key    string
	issued bool
}

func (f *metadataFakeIssuer) IssuerKey() string { return f.key }

func (f *metadataFakeIssuer) Issue(context.Context, *x509.CertificateRequest) (*IssuedCertificate, error) {
	f.issued = true
	return &IssuedCertificate{Certificate: []byte("replacement certificate")}, nil
}

func TestIssuerMetadataMismatchTriggersReissue(t *testing.T) {
	ctx := context.Background()
	domain := "issuer-metadata-mismatch.example"
	storage := &FileStorage{Path: t.TempDir()}
	issuer := &metadataFakeIssuer{key: "current-issuer"}
	cfg := newWithCache(new(Cache), Config{
		Issuers: []Issuer{issuer},
		Storage: storage,
		Logger:  zap.NewNop(),
	})

	err := cfg.saveCertResource(ctx, issuer, CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("stale certificate"),
		PrivateKeyPEM:  []byte("stale private key"),
		IssuerKey:      "previous-issuer",
	})
	if err != nil {
		t.Fatalf("seeding mismatched resource: %v", err)
	}

	if cfg.storageHasCertResources(ctx, issuer, domain) {
		t.Fatal("resource with mismatched issuer metadata should not be considered present")
	}
	if cfg.storageHasCertResourcesAnyIssuer(ctx, domain) {
		t.Fatal("mismatched resource should not satisfy any-issuer existence check")
	}
	if _, err := cfg.loadCertResourceAnyIssuer(ctx, domain, storage); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("mismatched resource should be skipped as not found, got error: %v", err)
	}

	if err := cfg.ObtainCertSync(ctx, domain); err != nil {
		t.Fatalf("ObtainCertSync should replace mismatched resource: %v", err)
	}
	if !issuer.issued {
		t.Fatal("expected configured issuer to issue a replacement certificate")
	}

	loaded, err := cfg.loadCertResource(ctx, issuer, domain, storage)
	if err != nil {
		t.Fatalf("loading replacement metadata: %v", err)
	}
	if loaded.IssuerKey != issuer.IssuerKey() {
		t.Fatalf("persisted issuer key = %q, want %q", loaded.IssuerKey, issuer.IssuerKey())
	}
	if !cfg.storageHasCertResourcesAnyIssuer(ctx, domain) {
		t.Fatal("replacement resource with matching metadata should be considered present")
	}
}

func TestIssuerMetadataLegacyResourceUsesPathIdentity(t *testing.T) {
	ctx := context.Background()
	domain := "issuer-metadata-legacy.example"
	storage := &FileStorage{Path: t.TempDir()}
	issuer := &metadataFakeIssuer{key: "path-issuer"}
	cfg := newWithCache(new(Cache), Config{
		Issuers: []Issuer{issuer},
		Storage: storage,
		Logger:  zap.NewNop(),
	})

	assets := map[string][]byte{
		StorageKeys.SiteCert(issuer.IssuerKey(), domain):       []byte("legacy certificate"),
		StorageKeys.SitePrivateKey(issuer.IssuerKey(), domain): []byte("legacy key"),
		StorageKeys.SiteMeta(issuer.IssuerKey(), domain):       []byte(`{"sans":["issuer-metadata-legacy.example"]}`),
	}
	for key, value := range assets {
		if err := storage.Store(ctx, key, value); err != nil {
			t.Fatalf("storing %s: %v", key, err)
		}
	}

	if !cfg.storageHasCertResources(ctx, issuer, domain) {
		t.Fatal("legacy metadata without issuer_key should be accepted via its storage path")
	}
	loaded, err := cfg.loadCertResource(ctx, issuer, domain, storage)
	if err != nil {
		t.Fatalf("loading legacy resource: %v", err)
	}
	if loaded.IssuerKey != issuer.IssuerKey() {
		t.Fatalf("loaded issuer key = %q, want path issuer %q", loaded.IssuerKey, issuer.IssuerKey())
	}
}
