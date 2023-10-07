BINARY_NAME=auth
 
all: ${BINARY_NAME} test
 
${BINARY_NAME}:
	go build -o ${BINARY_NAME} *.go
 
run: ${BINARY_NAME}
	BASE_URL="http://carenaggio.example.com:8080" JWT_KEY="UNSAFE_KEY" ./${BINARY_NAME}

image:
	podman build -t ghcr.io/carenaggio/auth .

image-push: image
	podman push ghcr.io/carenaggio/auth

clean:
	go clean
	rm -f ${BINARY_NAME}
