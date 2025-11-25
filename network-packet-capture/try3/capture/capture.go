package capture

import (
	"encoding/base64"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Len       int       `json:"len"`

	// L2
	SrcMAC       string `json:"src_mac,omitempty"`
	DstMAC       string `json:"dst_mac,omitempty"`
	EthernetType string `json:"ether_type,omitempty"`

	// L3
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst,omitempty"`
	IPVersion string `json:"ip_version,omitempty"`
	TTL       uint8  `json:"ttl,omitempty"`
	TOS       uint8  `json:"tos,omitempty"`
	HopLimit  uint8  `json:"hop_limit,omitempty"`
	FlowLabel uint32 `json:"flow_label,omitempty"`
	Fragment  uint16 `json:"fragment_offset,omitempty"`
	Flags     string `json:"flags,omitempty"`

	RawBase64 string `json:"raw_base64,omitempty"`

	raw []byte
	ci  gopacket.CaptureInfo
}

type RingBuffer struct {
	buf    []*PacketEntry
	cap    int
	start  int
	count  int
	mu     sync.RWMutex
	nextID int64
}

var Buffer *RingBuffer

func InitBuffer(capacity int) {
	Buffer = &RingBuffer{
		buf: make([]*PacketEntry, capacity),
		cap: capacity,
	}
}

func (r *RingBuffer) Append(p *PacketEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.count < r.cap {
		idx := (r.start + r.count) % r.cap
		r.buf[idx] = p
		r.count++
	} else {
		r.buf[r.start] = p
		r.start = (r.start + 1) % r.cap
	}
}

func (r *RingBuffer) List(n int) []*PacketEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if n <= 0 || n > r.count {
		n = r.count
	}

	out := make([]*PacketEntry, 0, n)
	for i := r.count - n; i < r.count; i++ {
		idx := (r.start + i) % r.cap
		out = append(out, r.buf[idx])
	}
	return out
}

func (r *RingBuffer) GetByID(id int64) *PacketEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < r.count; i++ {
		idx := (r.start + i) % r.cap
		if r.buf[idx] != nil && r.buf[idx].ID == id {
			return r.buf[idx]
		}
	}
	return nil
}

func StartCapture(iface string, snap int32, promisc bool, filter string) error {
	handle, err := pcap.OpenLive(iface, snap, promisc, pcap.BlockForever)
	if err != nil {
		return err
	}

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Printf("BPF filter error: %v", err)
		}
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	go func() {
		for p := range packets {
			if p == nil {
				continue
			}

			id := atomic.AddInt64(&Buffer.nextID, 1)
			meta := p.Metadata().CaptureInfo
			raw := p.Data()

			entry := &PacketEntry{
				ID:        id,
				Timestamp: meta.Timestamp,
				Len:       len(raw),
				raw:       append([]byte(nil), raw...),
				ci:        meta,
			}

			// L2 parsing
			if eth := p.Layer(layers.LayerTypeEthernet); eth != nil {
				e := eth.(*layers.Ethernet)
				entry.SrcMAC = e.SrcMAC.String()
				entry.DstMAC = e.DstMAC.String()
				entry.EthernetType = e.EthernetType.String()
			}

			// L3 parsing
			if ip4 := p.Layer(layers.LayerTypeIPv4); ip4 != nil {
				ipv4 := ip4.(*layers.IPv4)
				entry.IPVersion = "IPv4"
				entry.Src = ipv4.SrcIP.String()
				entry.Dst = ipv4.DstIP.String()
				entry.TTL = ipv4.TTL
				entry.TOS = ipv4.TOS
				entry.Flags = ipv4.Flags.String()
				entry.Fragment = ipv4.FragOffset
			}
			if ip6 := p.Layer(layers.LayerTypeIPv6); ip6 != nil {
				ipv6 := ip6.(*layers.IPv6)
				entry.IPVersion = "IPv6"
				entry.Src = ipv6.SrcIP.String()
				entry.Dst = ipv6.DstIP.String()
				entry.HopLimit = ipv6.HopLimit
				entry.FlowLabel = ipv6.FlowLabel
				entry.TrafficClass = ipv6.TrafficClass
			}

			if tr := p.TransportLayer(); tr != nil {
				entry.Proto = tr.LayerType().String()
			}

			entry.RawBase64 = base64.StdEncoding.EncodeToString(raw)
			Buffer.Append(entry)
		}
	}()

	return nil
}

func (p *PacketEntry) Raw() []byte {
	return p.raw
}

func (p *PacketEntry) CaptureInfo() gopacket.CaptureInfo {
	return p.ci
}
