IMG ?= k8s-depscan-operator:latest
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.22.0

.PHONY: build test generate generate-deepcopy generate-crd generate-rbac image docs docs-build

build:
	go build ./...

test:
	go test ./...

# Regenerate deepcopy, CRDs and RBAC after changing api/ types or markers.
generate: generate-deepcopy generate-crd generate-rbac

# Regenerate the deepcopy methods (zz_generated.deepcopy.go) from api/ types.
generate-deepcopy:
	$(CONTROLLER_GEN) object paths=./api/...

# Regenerate the CRD manifests from api/ types and kubebuilder markers.
generate-crd:
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/crd

# Regenerate the RBAC role from controller markers.
generate-rbac:
	$(CONTROLLER_GEN) rbac:roleName=depscan-operator paths="{./internal/...,./cmd/...}" output:rbac:artifacts:config=config/rbac

image:
	docker build -t $(IMG) .

# Serve the documentation site locally with live reload at http://127.0.0.1:8000.
docs:
	mkdocs serve

# Build the static documentation site into ./site (strict: warnings fail).
docs-build:
	mkdocs build --strict
