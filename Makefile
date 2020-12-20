PROG_NAME := "prom-collector"
IMAGE_NAME := "pschou/prom-collector"
VERSION := "0.1"


build:
	CGO_ENABLED=0 go build -o ${PROG_NAME} main.go
	CGO_ENABLED=0 go build -o prom-satellite satellite.go

docker: build
	docker build -f Dockerfile --tag ${IMAGE_NAME}:${VERSION} .
	docker build -f Dockerfile_sat --tag prom-satellite:${VERSION} .
	docker push ${IMAGE_NAME}:${VERSION}; \
	docker push prom-satellite:${VERSION}; \
