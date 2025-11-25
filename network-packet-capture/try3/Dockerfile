FROM golang:1.21-bullseye

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
    
WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o pcsrv ./main.go

ENTRYPOINT ["/app/pcsrv"]

# Run with:
# docker run --cap-add=NET_RAW --cap-add=NET_ADMIN -e IFACE=eth0 -p 8080:8080 pcsrv:latest

