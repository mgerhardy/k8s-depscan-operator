IMG ?= k8s-depscan-operator:latest

.PHONY: build test generate image

build:
	go build ./...

test:
	go test ./...

# Regenerate deepcopy, CRDs and RBAC after changing api/ types or markers.
generate:
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.3 object paths=./api/...
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.3 crd paths=./api/... output:crd:artifacts:config=config/crd
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.3 rbac:roleName=depscan-operator paths=./internal/... output:rbac:artifacts:config=config/rbac

image:
	docker build -t $(IMG) .
