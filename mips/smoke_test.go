package mips

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	singtun "github.com/sagernet/sing-tun"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
)

type testDevice struct {
	inbound   chan []byte
	outbound  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestDevice() *testDevice {
	return &testDevice{
		inbound:  make(chan []byte, 16),
		outbound: make(chan []byte, 16),
		closed:   make(chan struct{}),
	}
}

func (d *testDevice) Read(p []byte) (int, error) {
	select {
	case packet := <-d.inbound:
		return copy(p, packet), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *testDevice) Write(p []byte) (int, error) {
	packet := make([]byte, len(p))
	copy(packet, p)
	select {
	case d.outbound <- packet:
		return len(p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *testDevice) Name() (string, error)                    { return "test0", nil }
func (d *testDevice) Start() error                             { return nil }
func (d *testDevice) UpdateRouteOptions(singtun.Options) error { return nil }
func (d *testDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

var _ singtun.Tun = (*testDevice)(nil)

type testPacket struct {
	source      v2rayNet.Destination
	destination v2rayNet.Destination
	payload     []byte
	writeBack   func([]byte, *net.UDPAddr) (int, error)
}

type testHandler struct {
	conns   chan net.Conn
	packets chan *testPacket
}

func newTestHandler() *testHandler {
	return &testHandler{conns: make(chan net.Conn, 4), packets: make(chan *testPacket, 4)}
}

func (h *testHandler) NewConnection(source v2rayNet.Destination, destination v2rayNet.Destination, conn net.Conn) {
	h.conns <- conn
}

func (h *testHandler) NewPacket(source v2rayNet.Destination, destination v2rayNet.Destination, data *buf.Buffer, writeBack func([]byte, *net.UDPAddr) (int, error)) {
	payload := append([]byte(nil), data.Bytes()...)
	data.Release()
	h.packets <- &testPacket{source: source, destination: destination, payload: payload, writeBack: writeBack}
}

func checksumBytes(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func pseudoHeaderSum(source netip.Addr, destination netip.Addr, protocol byte, length int) uint32 {
	var sum uint32
	if source.Is4() {
		source4, destination4 := source.As4(), destination.As4()
		sum = checksumBytes(sum, source4[:])
		sum = checksumBytes(sum, destination4[:])
		sum += uint32(protocol)
		sum += uint32(length)
		return sum
	}
	source16, destination16 := source.As16(), destination.As16()
	sum = checksumBytes(sum, source16[:])
	sum = checksumBytes(sum, destination16[:])
	sum += uint32(length >> 16)
	sum += uint32(length & 0xffff)
	sum += uint32(protocol)
	return sum
}

func buildIPv4(source netip.Addr, destination netip.Addr, protocol byte, payload []byte) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(header[4:], 1)
	header[8] = 64
	header[9] = protocol
	source4, destination4 := source.As4(), destination.As4()
	copy(header[12:16], source4[:])
	copy(header[16:20], destination4[:])
	binary.BigEndian.PutUint16(header[10:], finishChecksum(checksumBytes(0, header)))
	return append(header, payload...)
}

func buildIPv6(source netip.Addr, destination netip.Addr, nextHeader byte, payload []byte) []byte {
	header := make([]byte, 40)
	header[0] = 0x60
	binary.BigEndian.PutUint16(header[4:], uint16(len(payload)))
	header[6] = nextHeader
	header[7] = 64
	source16, destination16 := source.As16(), destination.As16()
	copy(header[8:24], source16[:])
	copy(header[24:40], destination16[:])
	return append(header, payload...)
}

func buildTCP(source netip.Addr, destination netip.Addr, sourcePort uint16, destinationPort uint16, seq uint32, ack uint32, flags byte, payload []byte) []byte {
	segment := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(segment[0:], sourcePort)
	binary.BigEndian.PutUint16(segment[2:], destinationPort)
	binary.BigEndian.PutUint32(segment[4:], seq)
	binary.BigEndian.PutUint32(segment[8:], ack)
	segment[12] = 5 << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:], 65535)
	copy(segment[20:], payload)
	sum := pseudoHeaderSum(source, destination, 6, len(segment))
	binary.BigEndian.PutUint16(segment[16:], finishChecksum(checksumBytes(sum, segment)))
	if source.Is4() {
		return buildIPv4(source, destination, 6, segment)
	}
	return buildIPv6(source, destination, 6, segment)
}

func buildUDP(source netip.Addr, destination netip.Addr, sourcePort uint16, destinationPort uint16, payload []byte) []byte {
	datagram := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(datagram[0:], sourcePort)
	binary.BigEndian.PutUint16(datagram[2:], destinationPort)
	binary.BigEndian.PutUint16(datagram[4:], uint16(len(datagram)))
	copy(datagram[8:], payload)
	sum := pseudoHeaderSum(source, destination, 17, len(datagram))
	checksum := finishChecksum(checksumBytes(sum, datagram))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(datagram[6:], checksum)
	return buildIPv4(source, destination, 17, datagram)
}

func buildICMPEcho(source netip.Addr, destination netip.Addr, id uint16, seq uint16, payload []byte) []byte {
	message := make([]byte, 8+len(payload))
	message[0] = 8
	binary.BigEndian.PutUint16(message[4:], id)
	binary.BigEndian.PutUint16(message[6:], seq)
	copy(message[8:], payload)
	binary.BigEndian.PutUint16(message[2:], finishChecksum(checksumBytes(0, message)))
	return buildIPv4(source, destination, 1, message)
}

func parseIPv4(t *testing.T, packet []byte) (netip.Addr, netip.Addr, byte, []byte) {
	t.Helper()
	if len(packet) < 20 || packet[0]>>4 != 4 {
		t.Fatalf("not an IPv4 packet: % x", packet)
	}
	headerLength := int(packet[0]&0x0f) * 4
	return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[9], packet[headerLength:]
}

func parseTCP(t *testing.T, packet []byte) (uint16, uint16, uint32, uint32, byte, []byte) {
	t.Helper()
	_, _, protocol, segment := parseIPv4(t, packet)
	if protocol != 6 || len(segment) < 20 {
		t.Fatalf("not a TCP segment: % x", packet)
	}
	headerLength := int(segment[12]>>4) * 4
	return binary.BigEndian.Uint16(segment[0:]), binary.BigEndian.Uint16(segment[2:]),
		binary.BigEndian.Uint32(segment[4:]), binary.BigEndian.Uint32(segment[8:]),
		segment[13], segment[headerLength:]
}

func parseUDP(t *testing.T, packet []byte) (uint16, uint16, []byte) {
	t.Helper()
	_, _, protocol, datagram := parseIPv4(t, packet)
	if protocol != 17 || len(datagram) < 8 {
		t.Fatalf("not a UDP datagram: % x", packet)
	}
	return binary.BigEndian.Uint16(datagram[0:]), binary.BigEndian.Uint16(datagram[2:]), datagram[8:]
}

func parseICMP(t *testing.T, packet []byte) (byte, uint16, uint16, []byte) {
	t.Helper()
	_, _, protocol, message := parseIPv4(t, packet)
	if protocol != 1 || len(message) < 8 {
		t.Fatalf("not an ICMP message: % x", packet)
	}
	return message[0], binary.BigEndian.Uint16(message[4:]), binary.BigEndian.Uint16(message[6:]), message[8:]
}

func waitPacket(t *testing.T, device *testDevice) []byte {
	t.Helper()
	select {
	case packet := <-device.outbound:
		return packet
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for device output")
		return nil
	}
}

func testOptions(device *testDevice, handler *testHandler) Options {
	return Options{
		Device:  device,
		MTU:     1500,
		Addr4:   netip.MustParseAddr("172.19.0.1"),
		Addr6:   netip.MustParseAddr("fdfe:dcba:9876::1"),
		Handler: handler,
	}
}

func TestSmokeTCP(t *testing.T) {
	device := newTestDevice()
	handler := newTestHandler()
	stack, err := New(testOptions(device, handler))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	source := netip.MustParseAddr("10.0.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	device.inbound <- buildTCP(source, destination, 40000, 443, 1000, 0, 0x02, nil)

	_, destinationPort, serverSeq, serverAck, flags, _ := parseTCP(t, waitPacket(t, device))
	if flags != 0x12 {
		t.Fatalf("expected SYN-ACK, got flags %#x", flags)
	}
	if destinationPort != 40000 {
		t.Fatalf("unexpected destination port %d", destinationPort)
	}
	if serverAck != 1001 {
		t.Fatalf("unexpected acknowledgment %d", serverAck)
	}
	device.inbound <- buildTCP(source, destination, 40000, 443, 1001, serverSeq+1, 0x10, nil)

	var conn net.Conn
	select {
	case conn = <-handler.conns:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not receive the connection")
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != "10.0.0.2:40000" {
		t.Fatalf("unexpected remote address %s", conn.RemoteAddr())
	}
	if conn.LocalAddr().String() != "1.1.1.1:443" {
		t.Fatalf("unexpected local address %s", conn.LocalAddr())
	}
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, payload := parseTCP(t, waitPacket(t, device))
	if string(payload) != "hello" {
		t.Fatalf("unexpected payload %q", payload)
	}
}

func TestSmokeUDP(t *testing.T) {
	device := newTestDevice()
	handler := newTestHandler()
	stack, err := New(testOptions(device, handler))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	source := netip.MustParseAddr("10.0.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	device.inbound <- buildUDP(source, destination, 40000, 53, []byte("ping"))

	var packet *testPacket
	select {
	case packet = <-handler.packets:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not receive the datagram")
	}
	if string(packet.payload) != "ping" {
		t.Fatalf("unexpected payload %q", packet.payload)
	}
	if packet.destination.Address.String() != "1.1.1.1" || packet.destination.Port != 53 {
		t.Fatalf("unexpected destination %s", packet.destination)
	}
	if packet.source.Address.String() != "10.0.0.2" || packet.source.Port != 40000 {
		t.Fatalf("unexpected source %s", packet.source)
	}
	n, err := packet.writeBack([]byte("pong"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("unexpected write back length %d", n)
	}
	reply := waitPacket(t, device)
	sourceAddress, destinationAddress, _, _ := parseIPv4(t, reply)
	if sourceAddress.String() != "1.1.1.1" || destinationAddress.String() != "10.0.0.2" {
		t.Fatalf("unexpected reply addresses %s -> %s", sourceAddress, destinationAddress)
	}
	sourcePort, destinationPort, payload := parseUDP(t, reply)
	if sourcePort != 53 || destinationPort != 40000 || string(payload) != "pong" {
		t.Fatalf("unexpected reply %d -> %d %q", sourcePort, destinationPort, payload)
	}
}

func TestSmokeICMPEcho(t *testing.T) {
	device := newTestDevice()
	handler := newTestHandler()
	stack, err := New(testOptions(device, handler))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	source := netip.MustParseAddr("10.0.0.2")
	device.inbound <- buildICMPEcho(source, netip.MustParseAddr("172.19.0.1"), 7, 9, []byte("abcdefgh"))

	reply := waitPacket(t, device)
	sourceAddress, destinationAddress, _, _ := parseIPv4(t, reply)
	if sourceAddress.String() != "172.19.0.1" || destinationAddress.String() != "10.0.0.2" {
		t.Fatalf("unexpected reply addresses %s -> %s", sourceAddress, destinationAddress)
	}
	messageType, id, seq, payload := parseICMP(t, reply)
	if messageType != 0 || id != 7 || seq != 9 || string(payload) != "abcdefgh" {
		t.Fatalf("unexpected echo reply %d %d %d %q", messageType, id, seq, payload)
	}
}

func TestSmokeDiscardICMP(t *testing.T) {
	device := newTestDevice()
	handler := newTestHandler()
	options := testOptions(device, handler)
	options.DiscardICMP = true
	stack, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	source := netip.MustParseAddr("10.0.0.2")
	device.inbound <- buildICMPEcho(source, netip.MustParseAddr("172.19.0.1"), 7, 9, []byte("abcdefgh"))

	select {
	case packet := <-device.outbound:
		t.Fatalf("expected no reply, got % x", packet)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestSmokeDiscardIPv6(t *testing.T) {
	device := newTestDevice()
	handler := newTestHandler()
	stack, err := New(testOptions(device, handler))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	source := netip.MustParseAddr("fdfe:dcba:9876::2")
	destination := netip.MustParseAddr("2001:4860:4860::8888")
	device.inbound <- buildTCP(source, destination, 40000, 443, 1000, 0, 0x02, nil)

	select {
	case conn := <-handler.conns:
		t.Fatalf("expected no connection, got %s", conn.RemoteAddr())
	case <-time.After(500 * time.Millisecond):
	}
}

func TestSmokeLowMTU(t *testing.T) {
	device := newTestDevice()
	handler := newTestHandler()
	options := testOptions(device, handler)
	options.MTU = 1200
	options.EnableIPv6 = true
	stack, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	source := netip.MustParseAddr("10.0.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	device.inbound <- buildUDP(source, destination, 40000, 53, []byte("ping"))

	select {
	case packet := <-handler.packets:
		if string(packet.payload) != "ping" {
			t.Fatalf("unexpected payload %q", packet.payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not receive the datagram")
	}
}
