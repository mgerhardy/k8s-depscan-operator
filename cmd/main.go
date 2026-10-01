package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/controller"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(depscanv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var secureMetrics bool
	var probeAddr string
	var enableLeaderElection bool
	var operatorNamespace string
	var maxConcurrentReconciles int

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8443", "The address the metric endpoint binds to.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"Serve metrics over HTTPS and require an authenticated, authorized caller (get on the /metrics non-resource URL). "+
			"Set to false to serve plain, unauthenticated HTTP.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.StringVar(&operatorNamespace, "operator-namespace", envOr("OPERATOR_NAMESPACE", "depscan-system"),
		"Namespace where the operator runs and creates scan Jobs by default.")
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", 4,
		"How many reports (and pods) are reconciled in parallel. Scan concurrency itself is capped by maxConcurrentScans.")
	// Production logging (JSON, no stack traces on warnings, no panics on
	// DPanic) unless --zap-devel is passed.
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	restCfg := ctrl.GetConfigOrDie()

	// Load the config before any controller runs, straight from the API
	// server: the job namespace scopes the manager's caches, and reconcilers
	// refuse to act until a config is loaded. Fail loudly (and let the pod
	// restart) rather than run without one.
	directClient, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to build API client")
		os.Exit(1)
	}
	cfgResolver := &controller.ConfigResolver{OperatorNamespace: operatorNamespace}
	if err := loadConfig(cfgResolver, directClient); err != nil {
		setupLog.Error(err, "unable to load DepScanConfig")
		os.Exit(1)
	}
	if vc := cfgResolver.Get().VDBCache; !vc.Enabled {
		setupLog.Info("WARNING: vdbCache is disabled; every scan downloads the full vulnerability database " +
			"into node-local scratch space (bounded by vdbCache.size). Enable vdbCache for production.")
	}
	jobNS := controller.JobNamespace(cfgResolver.Get(), operatorNamespace)
	inJobNS := cache.ByObject{Namespaces: map[string]cache.Config{jobNS: {}}}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOptions(metricsAddr, secureMetrics),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "depscan-operator.depscan.io",
		Cache: cache.Options{
			DefaultTransform: cache.TransformStripManagedFields(),
			// Operator-created objects live only in the job namespace; do
			// not watch them cluster-wide.
			ByObject: map[client.Object]cache.ByObject{
				&batchv1.Job{}:                  inJobNS,
				&corev1.PersistentVolumeClaim{}: inJobNS,
			},
		},
		Client: client.Options{Cache: &client.CacheOptions{
			// Never mirror Secrets (or ConfigMaps) cluster-wide in operator
			// memory; the few the operator needs are read by name.
			DisableFor: []client.Object{&corev1.Secret{}, &corev1.ConfigMap{}},
		}},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	cfgResolver.Client = mgr.GetClient()

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		setupLog.Error(err, "unable to build clientset")
		os.Exit(1)
	}

	if err := (&controller.PodReconciler{
		Client:                  mgr.GetClient(),
		Config:                  cfgResolver,
		MaxConcurrentReconciles: maxConcurrentReconciles,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

	reportReconciler := &controller.DepScanReportReconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Clientset:         clientset,
		Recorder:          mgr.GetEventRecorder("depscan-operator"),
		Config:            cfgResolver,
		OperatorNamespace: operatorNamespace,

		MaxConcurrentReconciles: maxConcurrentReconciles,
	}
	if err := reportReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "DepScanReport")
		os.Exit(1)
	}

	if err := mgr.Add(vdbMaintainer{reconciler: reportReconciler}); err != nil {
		setupLog.Error(err, "unable to add vdb maintainer")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Keep the config cache warm. The resolver reads the "default"
	// DepScanConfig; a missing object falls back to built-in defaults.
	if err := mgr.Add(configRefresher{
		resolver: cfgResolver, cache: mgr.GetCache(),
		operatorNamespace: operatorNamespace, jobNamespace: jobNS,
	}); err != nil {
		setupLog.Error(err, "unable to add config refresher")
		os.Exit(1)
	}

	if err := mgr.Add(controller.ReportPruner{
		Client:            mgr.GetClient(),
		Config:            cfgResolver,
		OperatorNamespace: operatorNamespace,
		Interval:          time.Hour,
	}); err != nil {
		setupLog.Error(err, "unable to add report pruner")
		os.Exit(1)
	}

	setupLog.Info("starting manager", "operatorNamespace", operatorNamespace)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// metricsOptions serves metrics over HTTPS (self-signed unless certificates are
// provided) behind Kubernetes TokenReview/SubjectAccessReview authn/authz, or
// as plain HTTP when secure is false. The metrics reveal which namespaces carry
// which vulnerabilities, so they are not public by default.
func metricsOptions(addr string, secure bool) metricsserver.Options {
	opts := metricsserver.Options{BindAddress: addr, SecureServing: secure}
	if secure {
		opts.FilterProvider = filters.WithAuthenticationAndAuthorization
		// HTTP/2 is disabled to avoid the stream-reset DoS class
		// (CVE-2023-44487, CVE-2023-39325); scrapers use HTTP/1.1.
		opts.TLSOpts = []func(*tls.Config){func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} }}
	}
	return opts
}

// loadConfig performs the initial config load, retrying transient API errors
// for up to two minutes.
func loadConfig(res *controller.ConfigResolver, reader client.Reader) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var err error
	for {
		if err = res.Load(ctx, reader); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(5 * time.Second):
		}
	}
}

// configRefresher reloads the DepScanConfig into the resolver whenever it
// changes (informer events), with a slow periodic reload as a safety net.
//
// The caches are scoped to the job namespace chosen at startup, so a change
// of jobNamespace stops the manager (and thereby restarts the pod) to re-scope
// them.
type configRefresher struct {
	resolver          *controller.ConfigResolver
	cache             cache.Cache
	operatorNamespace string
	jobNamespace      string
}

func (c configRefresher) Start(ctx context.Context) error {
	l := ctrl.Log.WithName("config")
	moved := make(chan string, 1)
	refresh := func() {
		if err := c.resolver.Refresh(ctx); err != nil {
			l.Error(err, "refresh DepScanConfig (keeping the previous config)")
			return
		}
		if ns := controller.JobNamespace(c.resolver.Get(), c.operatorNamespace); ns != c.jobNamespace {
			select {
			case moved <- ns:
			default:
			}
		}
	}
	inf, err := c.cache.GetInformer(ctx, &depscanv1alpha1.DepScanConfig{})
	if err != nil {
		return err
	}
	if _, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { refresh() },
		UpdateFunc: func(any, any) { refresh() },
		DeleteFunc: func(any) { refresh() },
	}); err != nil {
		return err
	}
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	refresh()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refresh()
		case ns := <-moved:
			return fmt.Errorf("jobNamespace changed from %q to %q; restarting to re-scope caches", c.jobNamespace, ns)
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// RBAC for the authenticated metrics endpoint.
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// vdbMaintainer drives the VDB cache lifecycle (prime observation, refresh,
// garbage collection) independently of scan demand.
type vdbMaintainer struct {
	reconciler *controller.DepScanReportReconciler
}

func (g vdbMaintainer) Start(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			g.reconciler.MaintainVDB(ctx)
		}
	}
}
