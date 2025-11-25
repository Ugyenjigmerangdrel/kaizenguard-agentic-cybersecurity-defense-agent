package capture

import (
	"encoding/base64"
	"log"
	"strings"
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
	Src          string `json:"src,omitempty"`
	Dst          string `json:"dst,omitempty"`
	IPVersion    string `json:"ip_version,omitempty"`
	TTL          uint8  `json:"ttl,omitempty"`
	TOS          uint8  `json:"tos,omitempty"`
	HopLimit     uint8  `json:"hop_limit,omitempty"`
	FlowLabel    uint32 `json:"flow_label,omitempty"`
	Fragment     uint16 `json:"fragment_offset,omitempty"`
	Flags        string `json:"flags,omitempty"`
	TrafficClass uint8  `json:"traffic_class,omitempty"`

	// L4
	L4      string `json:"l4,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`

	// TCP flags
	SYN    bool   `json:"syn,omitempty"`
	ACK    bool   `json:"ack,omitempty"`
	FIN    bool   `json:"fin,omitempty"`
	RST    bool   `json:"rst,omitempty"`
	PSH    bool   `json:"psh,omitempty"`
	URG    bool   `json:"urg,omitempty"`
	Window uint16 `json:"window,omitempty"`
	Seq    uint32 `json:"seq,omitempty"`
	AckNum uint32 `json:"ack_num,omitempty"`

	// UDP
	UDPLen int `json:"udp_length,omitempty"`

	// L7 Metadata
	DNSQuery      string `json:"dns_query,omitempty"`
	HTTPMethod    string `json:"http_method,omitempty"`
	HTTPHost      string `json:"http_host,omitempty"`
	HTTPPath      string `json:"http_path,omitempty"`
	HTTPUserAgent string `json:"http_user_agent,omitempty"`
	SSDP          bool   `json:"ssdp,omitempty"`
	MDNS          bool   `json:"mdns,omitempty"`

	Protocol string `json:"protocol,omitempty"`

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

	subMu sync.Mutex
	subs  map[int]chan *PacketEntry
}

var Buffer *RingBuffer

func InitBuffer(capacity int) {
	Buffer = &RingBuffer{
		buf:  make([]*PacketEntry, capacity),
		cap:  capacity,
		subs: make(map[int]chan *PacketEntry),
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

func (r *RingBuffer) Subscribe() (int, chan *PacketEntry) {
	r.subMu.Lock()
	defer r.subMu.Unlock()

	id := int(atomic.AddInt64(&r.nextID, 1))
	ch := make(chan *PacketEntry, 256)
	r.subs[id] = ch
	return id, ch
}

func (r *RingBuffer) Unsubscribe(id int) {
	r.subMu.Lock()
	defer r.subMu.Unlock()

	if ch, ok := r.subs[id]; ok {
		close(ch)
		delete(r.subs, id)
	}
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
				entry.Protocol = "IPv4"
			}
			if ip6 := p.Layer(layers.LayerTypeIPv6); ip6 != nil {
				ipv6 := ip6.(*layers.IPv6)
				entry.IPVersion = "IPv6"
				entry.Src = ipv6.SrcIP.String()
				entry.Dst = ipv6.DstIP.String()
				entry.HopLimit = ipv6.HopLimit
				entry.FlowLabel = ipv6.FlowLabel
				entry.TrafficClass = ipv6.TrafficClass
				entry.Protocol = "IPv6"
			}

			// L4 parsing (TCP/UDP)
			if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				entry.L4 = "TCP"
				entry.SrcPort = int(tcp.SrcPort)
				entry.DstPort = int(tcp.DstPort)

				entry.SYN = tcp.SYN
				entry.ACK = tcp.ACK
				entry.FIN = tcp.FIN
				entry.RST = tcp.RST
				entry.PSH = tcp.PSH
				entry.URG = tcp.URG
				entry.Window = tcp.Window
				entry.Seq = tcp.Seq
				entry.AckNum = tcp.Ack
				entry.Protocol = "TCP"
			}

			if udpLayer := p.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				entry.L4 = "UDP"
				entry.SrcPort = int(udp.SrcPort)
				entry.DstPort = int(udp.DstPort)
				entry.UDPLen = int(udp.Length)
				entry.Protocol = "UDP"
			}

			// L7 parsing

			// DNS
			if dnsLayer := p.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns := dnsLayer.(*layers.DNS)
				if len(dns.Questions) > 0 {
					entry.DNSQuery = string(dns.Questions[0].Name)
					entry.Protocol = "DNS"
				}
			}

			// HTTP (very basic heuristics)
			if app := p.ApplicationLayer(); app != nil {
				payload := string(app.Payload())

				if len(payload) > 4 && (payload[:3] == "GET" || payload[:4] == "POST") {
					entry.HTTPMethod = strings.Fields(payload)[0]
					lines := strings.Split(payload, "\n")
					for _, l := range lines {
						if strings.HasPrefix(l, "Host:") {
							entry.HTTPHost = strings.TrimSpace(strings.TrimPrefix(l, "Host:"))
						}
						if strings.HasPrefix(l, "User-Agent:") {
							entry.HTTPUserAgent = strings.TrimSpace(strings.TrimPrefix(l, "User-Agent:"))
						}
					}
					entry.Protocol = "HTTP"
				}

				// SSDP detection
				if strings.Contains(payload, "M-SEARCH") || strings.Contains(payload, "NOTIFY * HTTP/") {
					entry.SSDP = true
					entry.Protocol = "SSDP"
				}

				// mDNS
				if entry.SrcPort == 5353 || entry.DstPort == 5353 {
					entry.MDNS = true
					entry.Protocol = "mDNS"
				}
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
