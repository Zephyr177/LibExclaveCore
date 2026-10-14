/*
Copyright (C) 2026  dyhkwong

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package libexclavecore

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"time"

	singtun "github.com/sagernet/sing-tun"
	gHeader "github.com/sagernet/sing-tun/gtcpip/header"
	singbuf "github.com/sagernet/sing/common/buf"
	singbufio "github.com/sagernet/sing/common/bufio"
	SM "github.com/sagernet/sing/common/metadata"
	SN "github.com/sagernet/sing/common/network"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
)

// singTun adapts a sing-tun device and stack to the core's tun.Tun interface.
// It is used to back TunImplementationGVisor with sing-tun's "go" userspace stack.
type singTun struct {
	device singtun.Tun
	stack  singtun.Stack
}

func (t *singTun) Close() error {
	var err error
	if t.stack != nil {
		err = t.stack.Close()
	}
	if t.device != nil {
		if closeErr := t.device.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

// newSingTunDevice opens the packet device shared by every userspace stack.
func newSingTunDevice(config *TunConfig, t *Tun2ray) (singtun.Tun, singtun.Options, error) {
	mtu := config.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	tunOptions := singtun.Options{
		FileDescriptor: int(config.FileDescriptor),
		MTU:            uint32(mtu),
		// The fd is owned by VpnService; sing-tun only wraps it.
		EXP_ExternalConfiguration: true,
		Logger:                    singLogger{},
	}
	if t.addr4.IsValid() {
		tunOptions.Inet4Address = []netip.Prefix{netip.PrefixFrom(t.addr4, 32)}
	}
	if config.EnableIPv6 && t.addr6.IsValid() {
		tunOptions.Inet6Address = []netip.Prefix{netip.PrefixFrom(t.addr6, 128)}
	}

	device, err := singtun.New(tunOptions)
	if err != nil {
		return nil, singtun.Options{}, err
	}
	if err = device.Start(); err != nil {
		_ = device.Close()
		return nil, singtun.Options{}, err
	}
	return device, tunOptions, nil
}

func newSingTun(config *TunConfig, t *Tun2ray, discardIPv6Func func() bool) (*singTun, error) {
	device, tunOptions, err := newSingTunDevice(config, t)
	if err != nil {
		return nil, err
	}

	stack, err := singtun.NewStack("go", singtun.StackOptions{
		Context:    context.Background(),
		Tun:        device,
		TunOptions: tunOptions,
		Handler: &singHandler{
			tun:         t,
			enableIPv6:  config.EnableIPv6,
			discardICMP: config.DiscardICMP,
			discardIPv6: discardIPv6Func,
		},
		Logger:     singLogger{},
		UDPTimeout: 5 * time.Minute,
	})
	if err != nil {
		_ = device.Close()
		return nil, err
	}
	if err = stack.Start(); err != nil {
		_ = stack.Close()
		_ = device.Close()
		return nil, err
	}

	return &singTun{device: device, stack: stack}, nil
}

var _ singtun.Handler = (*singHandler)(nil)

// singHandler bridges sing-tun's handler callbacks to Tun2ray's inbound handling.
type singHandler struct {
	tun         *Tun2ray
	enableIPv6  bool
	discardICMP bool
	discardIPv6 func() bool
}

func (h *singHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) singtun.FlowVerdict {
	if h.discardICMP && (network == uint8(gHeader.ICMPv4ProtocolNumber) || network == uint8(gHeader.ICMPv6ProtocolNumber)) {
		newError("discarded ICMP to ", destination.Addr()).AtInfo().WriteToLog()
		return singtun.FlowVerdict{Action: singtun.ActionDrop}
	}
	if source.Addr().Is6() || destination.Addr().Is6() {
		if !h.enableIPv6 || (h.discardIPv6 != nil && h.discardIPv6()) {
			newError("discarded IPv6 to ", destination.Addr()).AtInfo().WriteToLog()
			return singtun.FlowVerdict{Action: singtun.ActionDrop}
		}
	}
	return singtun.FlowVerdict{Action: singtun.ActionAccept}
}

func (h *singHandler) NewDNSPacket(payload []byte, source SM.Socksaddr, destination SM.Socksaddr, writer SN.PacketWriter) {
	data := newPacketBuffer(payload)
	frontHeadroom := SN.CalculateFrontHeadroom(writer)
	writeBack := func(bytes []byte, addr *net.UDPAddr) (int, error) {
		replySource := destination
		if addr != nil {
			replySource = SM.SocksaddrFromNet(addr)
		}
		replyBuffer := singbuf.NewSize(frontHeadroom + len(bytes))
		replyBuffer.Resize(frontHeadroom, 0)
		_, _ = replyBuffer.Write(bytes)
		err := writer.WritePacket(replyBuffer, replySource)
		return len(bytes), err
	}
	h.tun.NewPacket(toV2RayDestination(source, v2rayNet.Network_UDP), toV2RayDestination(destination, v2rayNet.Network_UDP), data, writeBack)
}

// newPacketBuffer copies a payload into pooled core storage released by Tun2ray.
func newPacketBuffer(payload []byte) *buf.Buffer {
	data := buf.NewWithSize(int32(len(payload)))
	_, _ = data.Write(payload)
	return data
}

func (h *singHandler) NewConnectionEx(_ context.Context, conn net.Conn, source SM.Socksaddr, destination SM.Socksaddr, onClose SN.CloseHandlerFunc) {
	if !destination.IsIP() {
		_ = conn.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	h.tun.NewConnection(toV2RayDestination(source, v2rayNet.Network_TCP), toV2RayDestination(destination, v2rayNet.Network_TCP), conn)
	if onClose != nil {
		onClose(nil)
	}
}

func (h *singHandler) NewPacketConnectionEx(_ context.Context, conn SN.PacketConn, source SM.Socksaddr, destination SM.Socksaddr, onClose SN.CloseHandlerFunc) {
	if !destination.IsIP() {
		_ = conn.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	v2raySource := toV2RayDestination(source, v2rayNet.Network_UDP)
	frontHeadroom := SN.CalculateFrontHeadroom(conn)
	// Tun2ray keys sessions by source and retains only the writeBack of the
	// packet that opened one, so a single closure serves the whole connection.
	writeBack := func(bytes []byte, addr *net.UDPAddr) (int, error) {
		replyDestination := destination
		if addr != nil {
			replyDestination = SM.SocksaddrFromNet(addr)
		}
		replyBuffer := singbuf.NewSize(frontHeadroom + len(bytes))
		replyBuffer.Resize(frontHeadroom, 0)
		_, _ = replyBuffer.Write(bytes)
		err := conn.WritePacket(replyBuffer, replyDestination)
		return len(bytes), err
	}
	// The read waiter hands over the queued buffer itself, saving the copy
	// ReadPacket makes into a caller buffer.
	readWaiter, isReadWaiter := singbufio.CreatePacketReadWaiter(conn)
	if isReadWaiter {
		readWaiter.InitializeReadWaiter(SN.ReadWaitOptions{})
	}
	readSize := int(h.tun.mtu)
	if readSize <= 0 {
		readSize = 1500
	}
	var readErr error
	for {
		var (
			buffer            *singbuf.Buffer
			packetDestination SM.Socksaddr
			err               error
		)
		if isReadWaiter {
			buffer, packetDestination, err = readWaiter.WaitReadPacket()
		} else {
			buffer = singbuf.NewSize(readSize)
			packetDestination, err = conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
			}
		}
		if err != nil {
			readErr = err
			if errors.Is(readErr, io.ErrShortBuffer) {
				continue
			}
			break
		}
		if !packetDestination.IsIP() {
			packetDestination = destination
		}
		data := newPacketBuffer(buffer.Bytes())
		buffer.Release()
		h.tun.NewPacket(v2raySource, toV2RayDestination(packetDestination, v2rayNet.Network_UDP), data, writeBack)
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(readErr)
	}
}

func toV2RayDestination(destination SM.Socksaddr, network v2rayNet.Network) v2rayNet.Destination {
	return v2rayNet.Destination{
		Address: v2rayNet.IPAddress(destination.Addr.Unmap().AsSlice()),
		Port:    v2rayNet.Port(destination.Port),
		Network: network,
	}
}

// singLogger routes sing-tun logs to the core's Android log output.
type singLogger struct{}

func singLog(args []any) {
	log.Println(append([]any{"sing-tun:"}, args...)...)
}

func (singLogger) Trace(args ...any) {}
func (singLogger) Debug(args ...any) {}
func (singLogger) Info(args ...any)  { singLog(args) }
func (singLogger) Warn(args ...any)  { singLog(args) }
func (singLogger) Error(args ...any) { singLog(args) }

func (singLogger) Fatal(args ...any) {
	singLog(args)
	panic(args)
}

func (singLogger) Panic(args ...any) {
	singLog(args)
	panic(args)
}
