package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"packetservice/capture"

	"github.com/google/gopacket/pcapgo"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// List packets
func HandleListPackets(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			limit = v
		}
	}

	pkts := capture.Buffer.List(limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pkts)
}

// Get a single packet
func HandleGetPacket(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	pkt := capture.Buffer.GetByID(id)
	if pkt == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pkt)
}

// Export packets as PCAP
func HandleExportPCAP(w http.ResponseWriter, r *http.Request) {
	n := 100
	if s := r.URL.Query().Get("count"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			n = v
		}
	}

	pkts := capture.Buffer.List(n)

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=export-%d.pcap", time.Now().Unix()))

	writer := pcapgo.NewWriter(w)
	writer.WriteFileHeader(65535, 1)

	for _, p := range pkts {
		writer.WritePacket(p.CaptureInfo(), p.Raw())
	}
}

// WebSocket live streaming
func HandleWSStream(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	id, ch := capture.Buffer.Subscribe()
	defer capture.Buffer.Unsubscribe(id)

	for pkt := range ch {
		if err := conn.WriteJSON(pkt); err != nil {
			return
		}
	}
}
