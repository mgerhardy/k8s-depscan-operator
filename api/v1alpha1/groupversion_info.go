// Package v1alpha1 contains API Schema definitions for the depscan v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=depscan.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "depscan.io", Version: "v1alpha1"}

	// SchemeBuilder collects the functions that add this group's types to a
	// scheme. It uses apimachinery only, so the API package stays cheap to
	// import (controller-runtime's scheme.Builder is deprecated for this).
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme

	knownTypes []runtime.Object
)

// register records API types for addKnownTypes; called from the types' init.
func register(objs ...runtime.Object) {
	knownTypes = append(knownTypes, objs...)
}

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, knownTypes...)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
