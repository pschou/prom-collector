PROG_NAME := "prom-collector"
IMAGE_NAME := "pschou/prom-collector"
VERSION := "0.8"
FLAGS := "-s -w"


build:
	CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME} main.go
	upx --lzma ${PROG_NAME}
	CGO_ENABLED=0 go build -ldflags=${FLAGS} -o prom-satellite satellite.go
	upx --lzma prom-satellite

docker: build
	docker build -f Dockerfile --tag ${IMAGE_NAME}:${VERSION} .
	#docker build -f Dockerfile_sat --tag prom-satellite:${VERSION} .
	docker push ${IMAGE_NAME}:${VERSION};  
	#docker push prom-satellite:${VERSION};  
	docker save ${IMAGE_NAME}:${VERSION} > pschou_prom-collector.tar
