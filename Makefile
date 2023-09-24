BINARY_NAME=auth
 
all: ${BINARY_NAME} test
 
${BINARY_NAME}:
	go build -tags netgo -ldflags '-extldflags -static -s' -o ${BINARY_NAME} *.go
 
run: ${BINARY_NAME}
	BASE_URL="http://carenaggio.example.com:8080" JWT_KEY="UNSAFE_KEY" ./${BINARY_NAME}

container: ${BINARY_NAME}
	podman build -t ghcr.io/carenaggio/auth .

container-push: container
	podman push ghcr.io/carenaggio/auth

clean:
	go clean
	rm -f ${BINARY_NAME}
