package main

import (
	"context"
	"flag"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
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
	var probeAddr string
	var enableLeaderElection bool
	var operatorNamespace string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.StringVar(&operatorNamespace, "operator-namespace", envOr("OPERATOR_NAMESPACE", "depscan-system"),
		"Namespace where the operator runs and creates scan Jobs by default.")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	restCfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "depscan-operator.depscan.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		setupLog.Error(err, "unable to build clientset")
		os.Exit(1)
	}

	cfgResolver := &controller.ConfigResolver{
		Client:            mgr.GetClient(),
		OperatorNamespace: operatorNamespace,
	}

	if err := (&controller.PodReconciler{
		Client: mgr.GetClient(),
		Config: cfgResolver,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

	if err := (&controller.DepScanReportReconciler{
		Client:            mgr.GetClient(),
		Clientset:         clientset,
		Config:            cfgResolver,
		OperatorNamespace: operatorNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "DepScanReport")
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
	if err := mgr.Add(configRefresher{resolver: cfgResolver}); err != nil {
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

// configRefresher periodically reloads the DepScanConfig into the resolver.
type configRefresher struct {
	resolver *controller.ConfigResolver
}

func (c configRefresher) Start(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	_ = c.resolver.Refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = c.resolver.Refresh(ctx)
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
