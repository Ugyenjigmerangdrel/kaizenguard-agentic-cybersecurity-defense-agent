package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"packetservice/api"
	"packetservice/capture"
)

func main() {
	iface := os.Getenv("IFACE")
	if iface == "" {
		iface = "eth0"
	}

	capStr := os.Getenv("BUFFER_CAPACITY")
	capacity := 10000
	if capStr != "" {
		if v, err := strconv.Atoi(capStr); err == nil {
			capacity = v
		}
	}

	capture.InitBuffer(capacity)

	filter := os.Getenv("BPF_FILTER")

	if err := capture.StartCapture(iface, 65535, true, filter); err != nil {
		log.Fatalf("capture start error: %v", err)
	}

	http.HandleFunc("/packets", api.HandleListPackets)
	http.HandleFunc("/packets/", api.HandleGetPacket)
	http.HandleFunc("/export", api.HandleExportPCAP)
	http.HandleFunc("/ws", api.HandleWSStream)

	addr := ":8080"
	if a := os.Getenv("ADDR"); a != "" {
		addr = a
	}

	log.Printf("HTTP server running on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
