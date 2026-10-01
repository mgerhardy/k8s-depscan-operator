package controller

import (
	"context"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// DefaultConfigName is the conventional name of the single cluster-scoped
// DepScanConfig object the operator reads.
const DefaultConfigName = "default"

// ConfigResolver caches the active DepScanConfig spec so reconcilers can read
// it cheaply. It falls back to built-in defaults when no config object exists.
type ConfigResolver struct {
	Client            client.Client
	OperatorNamespace string

	mu   sync.RWMutex
	spec depscanv1alpha1.DepScanConfigSpec
}

// Defaults returns the built-in configuration used when no DepScanConfig
// object is present in the cluster.
func Defaults() depscanv1alpha1.DepScanConfigSpec {
	return depscanv1alpha1.DepScanConfigSpec{
		ScannerImage:       "ghcr.io/owasp-dep-scan/dep-scan:latest",
		CraneImage:         "gcr.io/go-containerregistry/crane:latest",
		RescanInterval:     metav1.Duration{Duration: 24 * time.Hour},
		JobTTLSeconds:      600,
		MaxConcurrentScans: 5,
	}
}

// Get returns the cached spec, applying defaults for any zero-valued fields.
func (c *ConfigResolver) Get() depscanv1alpha1.DepScanConfigSpec {
	c.mu.RLock()
	spec := c.spec
	c.mu.RUnlock()
	return withDefaults(spec)
}

// Refresh reloads the DepScanConfig named "default" from the cluster.
func (c *ConfigResolver) Refresh(ctx context.Context) error {
	var cfg depscanv1alpha1.DepScanConfig
	err := c.Client.Get(ctx, types.NamespacedName{Name: DefaultConfigName}, &cfg)
	if apierrors.IsNotFound(err) {
		c.mu.Lock()
		c.spec = Defaults()
		c.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.spec = cfg.Spec
	c.mu.Unlock()
	return nil
}

func withDefaults(spec depscanv1alpha1.DepScanConfigSpec) depscanv1alpha1.DepScanConfigSpec {
	d := Defaults()
	if spec.ScannerImage == "" {
		spec.ScannerImage = d.ScannerImage
	}
	if spec.CraneImage == "" {
		spec.CraneImage = d.CraneImage
	}
	if spec.RescanInterval.Duration == 0 {
		spec.RescanInterval = d.RescanInterval
	}
	if spec.JobTTLSeconds == 0 {
		spec.JobTTLSeconds = d.JobTTLSeconds
	}
	if spec.MaxConcurrentScans == 0 {
		spec.MaxConcurrentScans = d.MaxConcurrentScans
	}
	return spec
}
