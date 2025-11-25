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
)

// List packets (metadata only)
func HandleListPackets(w http.ResponseWriter, r *http.Request) {
    limit := 100
    if s := r.URL.Query().Get("limit"); s != "" {
        if v, err := strconv.Atoi(s); err == nil {
            limit = v
        }
    }

    packets := capture.Buffer.List(limit)
    out := make([]map[string]interface{}, 0, len(packets))

    for _, p := range packets {
        out = append(out, map[string]interface{}{
            "id":        p.ID,
            "timestamp": p.Timestamp,
            "len":       p.Len,
            "src":       p.Src,
            "dst":       p.Dst,
            "proto":     p.Proto,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(out)
}

// Get single packet (with raw)
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

// Export PCAP
func HandleExportPCAP(w http.ResponseWriter, r *http.Request) {
    n := 100
    if s := r.URL.Query().Get("count"); s != "" {
        if v, err := strconv.Atoi(s); err == nil {
            n = v
        }
    }

    packets := capture.Buffer.List(n)

    w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=export-%d.pcap", time.Now().Unix()))

    writer := pcapgo.NewWriter(w)
    writer.WriteFileHeader(65535, 1)

    for _, p := range packets {
        writer.WritePacket(p.CaptureInfo(), p.Raw())
    }
}

// SSE live stream
func HandleStream(w http.ResponseWriter, r *http.Request) {
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    // Basic implementation: poll buffer

    lastID := int64(0)

    for {
        packets := capture.Buffer.List(50)

        for _, p := range packets {
            if p.ID <= lastID {
                continue
            }

            data, _ := json.Marshal(p)
            fmt.Fprintf(w, "data: %s\n\n", data)
            flusher.Flush()

            lastID = p.ID
        }

        time.Sleep(1 * time.Second)
    }
}
