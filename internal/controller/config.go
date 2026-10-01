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

	mu     sync.RWMutex
	spec   depscanv1alpha1.DepScanConfigSpec
	loaded bool
}

// Defaults returns the built-in configuration used when no DepScanConfig
// object is present in the cluster.
func Defaults() depscanv1alpha1.DepScanConfigSpec {
	return depscanv1alpha1.DepScanConfigSpec{
		ScannerImage:       depscanv1alpha1.DefaultScannerImage,
		CraneImage:         depscanv1alpha1.DefaultCraneImage,
		ScanProfile:        "research",
		RescanInterval:     metav1.Duration{Duration: 24 * time.Hour},
		JobTTLSeconds:      600,
		MaxConcurrentScans: 5,
		ScanTimeout:        metav1.Duration{Duration: time.Hour},
		ScanWorkSizeLimit:  "20Gi",
		VDBCache:           &depscanv1alpha1.VDBCacheSpec{Enabled: true},
	}
}

// Get returns the cached spec, applying defaults for any zero-valued fields.
func (c *ConfigResolver) Get() depscanv1alpha1.DepScanConfigSpec {
	c.mu.RLock()
	spec := c.spec
	c.mu.RUnlock()
	return withDefaults(spec)
}

// Loaded reports whether a configuration has been read from the cluster at
// least once. Until then reconcilers must not act: the zero-value spec has no
// namespace include/exclude rules and would put every namespace in scope.
func (c *ConfigResolver) Loaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded
}

// Refresh reloads the DepScanConfig named "default" from the cluster. A
// missing object deliberately means built-in defaults; any other error keeps
// the previously loaded config.
func (c *ConfigResolver) Refresh(ctx context.Context) error {
	return c.Load(ctx, c.Client)
}

// Load reads the DepScanConfig through r (e.g. an uncached API reader before
// the manager's caches have started).
func (c *ConfigResolver) Load(ctx context.Context, r client.Reader) error {
	var cfg depscanv1alpha1.DepScanConfig
	err := r.Get(ctx, types.NamespacedName{Name: DefaultConfigName}, &cfg)
	spec := cfg.Spec
	if apierrors.IsNotFound(err) {
		spec = Defaults()
	} else if err != nil {
		return err
	}
	c.mu.Lock()
	c.spec = spec
	c.loaded = true
	c.mu.Unlock()
	return nil
}

// configNotLoadedRequeue is how soon a reconcile retries while no config has
// been loaded yet.
const configNotLoadedRequeue = 10 * time.Second

func withDefaults(spec depscanv1alpha1.DepScanConfigSpec) depscanv1alpha1.DepScanConfigSpec {
	d := Defaults()
	if spec.ScannerImage == "" {
		spec.ScannerImage = d.ScannerImage
	}
	if spec.CraneImage == "" {
		spec.CraneImage = d.CraneImage
	}
	if spec.ScanProfile == "" {
		spec.ScanProfile = d.ScanProfile
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
	if spec.ScanTimeout.Duration <= 0 {
		spec.ScanTimeout = d.ScanTimeout
	}
	if spec.ScanWorkSizeLimit == "" {
		spec.ScanWorkSizeLimit = d.ScanWorkSizeLimit
	}
	// An unset vdbCache means the (enabled) default cache, matching the CRD
	// default. Copy before filling so the cached spec is never mutated.
	vc := depscanv1alpha1.VDBCacheSpec{Enabled: true}
	if spec.VDBCache != nil {
		vc = *spec.VDBCache
	}
	if vc.Size == "" {
		vc.Size = depscanv1alpha1.DefaultVDBCacheSize
	}
	if vc.AccessMode == "" {
		vc.AccessMode = "ReadWriteOnce"
	}
	if vc.RefreshInterval.Duration <= 0 {
		vc.RefreshInterval = metav1.Duration{Duration: 24 * time.Hour}
	}
	if vc.PrimeTimeout.Duration <= 0 {
		vc.PrimeTimeout = metav1.Duration{Duration: 4 * time.Hour}
	}
	spec.VDBCache = &vc
	return spec
}
