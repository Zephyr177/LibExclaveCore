/*
Copyright (C) 2026 by nekohasekai <contact-sagernet@sekai.icu>

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

package mips

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/metacubex/mipstack"
	singtun "github.com/sagernet/sing-tun"

	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/libexclavecore/tun"
)

var _ tun.Tun = (*Tun)(nil)

// Options configures a mips stack over an already started packet device.
type Options struct {
	// Device is the packet link the stack reads and writes complete IP packets on.
	Device singtun.Tun
	// MTU bounds packets emitted by the stack. Zero selects 1500.
	MTU uint32
	// Addr4 and Addr6 are the interface addresses. Echo requests addressed to
	// them are answered by this core instead of the remote peer.
	Addr4 netip.Addr
	Addr6 netip.Addr
	// EnableIPv6 admits IPv6 flows, matching the device configuration.
	EnableIPv6 bool
	// DiscardICMP drops every ICMP message instead of answering it.
	DiscardICMP bool
	// DiscardIPv6 optionally drops IPv6 flows at runtime, for example after the
	// underlying network lost IPv6 connectivity.
	DiscardIPv6 func() bool
	// Handler receives every flow the stack cannot terminate on its own.
	Handler tun.Handler
}

// Tun runs the mihomo IP stack (github.com/metacubex/mipstack) over the same
// sing-tun packet device used by the other stacks, backing
// TunImplementationMIPS. It forwards every TCP, UDP, and ICMP flow to the
// handler and writes stack output back to the device.
//
// The stack owns no local addresses: every flow, including one addressed to the
// interface itself, is offered to the forwarders, so the core's admittance
// rules stay in one place.
type Tun struct {
	device      singtun.Tun
	mtu         uint32
	addr4       netip.Addr
	addr6       netip.Addr
	enableIPv6  bool
	discardICMP bool
	discardIPv6 func() bool
	handler     tun.Handler
	stack       *mipstack.Stack
}

// New creates the stack over options.Device, which must already be started.
func New(options Options) (*Tun, error) {
	if options.Handler == nil {
		return nil, newError("mips stack requires a handler")
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1500
	}
	t := &Tun{
		device:      options.Device,
		mtu:         mtu,
		addr4:       options.Addr4,
		addr6:       options.Addr6,
		enableIPv6:  options.EnableIPv6,
		discardICMP: options.DiscardICMP,
		discardIPv6: options.DiscardIPv6,
		handler:     options.Handler,
	}

	config := mipstack.Config{
		Promiscuous: true,
		MTU:         mtu,
		TCP: mipstack.TCPSocketDefaults{
			KeepAlive: true,
			KeepAliveConfig: mipstack.KeepAliveConfig{
				Idle:     15 * time.Second,
				Interval: 15 * time.Second,
			},
		},
	}
	// An addressless stack installs one default route per family, while IPv6
	// output requires at least 1280 bytes of MTU. A device below that bound
	// cannot carry IPv6 at all, which the kernel enforces as well, so keep such
	// links admitted by the IPv4 default route alone.
	if mtu < 1280 {
		config.Routes = []mipstack.Route{{Destination: netip.MustParsePrefix("0.0.0.0/0")}}
		if t.enableIPv6 {
			newError("IPv6 requires an MTU of at least 1280, ignoring it for the mips stack").AtWarning().WriteToLog()
		}
	}
	stack, err := mipstack.New(config)
	if err != nil {
		return nil, err
	}
	t.stack = stack
	if _, err = mipstack.NewTCPForwarder(stack, mipstack.TCPForwarderOptions{}, t.forwardTCP); err != nil {
		_ = stack.Close()
		return nil, err
	}
	if _, err = mipstack.NewUDPForwarder(stack, mipstack.UDPForwarderOptions{}, t.forwardUDP); err != nil {
		_ = stack.Close()
		return nil, err
	}
	if _, err = mipstack.NewICMPForwarder(stack, mipstack.ICMPForwarderOptions{}, t.forwardICMP); err != nil {
		_ = stack.Close()
		return nil, err
	}
	// A real packet device delivers complete packets with checksums validated
	// by the kernel, like every other stack in this core.
	switch t.device.(type) {
	case singtun.WinTun, singtun.LinuxTUN, singtun.DarwinTUN:
		var offload mipstack.RXChecksumOffload
		offload.SetIPv4Header(true).SetTCP(true).SetUDP(true)
		stack.SetRXChecksumOffload(offload)
	}
	if err = stack.Start(); err != nil {
		_ = stack.Close()
		return nil, err
	}
	go t.readLoop()
	go t.writeLoop()
	return t, nil
}

// Close stops the stack and the device. The read and write loops exit once the
// device reports the closure.
func (t *Tun) Close() error {
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

// dropFlow applies the core's IPv6 admittance rules to one flow. It mirrors the
// verdict the sing-tun handler returns for the same flow.
func (t *Tun) dropFlow(source netip.Addr, destination netip.Addr) bool {
	if source.Is6() || destination.Is6() {
		if !t.enableIPv6 || (t.discardIPv6 != nil && t.discardIPv6()) {
			newError("discarded IPv6 to ", destination).AtInfo().WriteToLog()
			return true
		}
	}
	return false
}

func (t *Tun) readLoop() {
	buffer := make([]byte, int(t.mtu))
	packets := make([][]byte, 1)
	var readRetry singtun.ReadRetry
	for {
		n, err := t.device.Read(buffer)
		if n > 0 {
			packets[0] = buffer[:n]
			_, _ = t.stack.Write(packets, 0)
		}
		if err != nil {
			if isClosedError(err) {
				return
			}
			if singtun.IsRecoverableReadError(err) {
				readRetry.Wait(err)
				continue
			}
			newError("read packet: ", err).AtDebug().WriteToLog()
			return
		}
		readRetry.Reset()
	}
}

func (t *Tun) writeLoop() {
	batchSize := t.stack.BatchSize()
	buffers := make([][]byte, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, int(t.mtu))
	}
	sizes := make([]int, batchSize)
	for {
		n, err := t.stack.Read(buffers, sizes, 0)
		for i := range n {
			if _, writeErr := t.device.Write(buffers[i][:sizes[i]]); writeErr != nil {
				if isClosedError(writeErr) {
					return
				}
				newError("write packet: ", writeErr).AtDebug().WriteToLog()
				break
			}
		}
		if err != nil {
			if isClosedError(err) {
				return
			}
			// Read already discarded the oversized packet; the rest of the
			// output queue is still deliverable.
			if errors.Is(err, io.ErrShortBuffer) {
				continue
			}
			newError("read stack packet: ", err).AtError().WriteToLog()
			return
		}
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, syscall.EBADF)
}

func toV2RayDestination(address netip.AddrPort, network v2rayNet.Network) v2rayNet.Destination {
	return v2rayNet.Destination{
		Address: v2rayNet.IPAddress(address.Addr().Unmap().AsSlice()),
		Port:    v2rayNet.Port(address.Port()),
		Network: network,
	}
}
