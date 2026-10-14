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
	"net"
	"net/netip"

	"github.com/metacubex/mipstack"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
)

func (t *Tun) forwardUDP(request *mipstack.UDPForwarderRequest) {
	flow := request.Flow()
	if t.dropFlow(flow.Source.Addr(), flow.Destination.Addr()) {
		_ = request.Drop()
		return
	}
	// The payload is only valid until this handler returns, while the responder
	// outlives it for as long as the core keeps the session. Tun2ray releases
	// the pooled copy.
	payload := request.Payload()
	data := buf.NewWithSize(int32(len(payload)))
	_, _ = data.Write(payload)
	responder, err := request.DetachForReplies()
	if err != nil {
		data.Release()
		return
	}
	writeBack := func(bytes []byte, addr *net.UDPAddr) (int, error) {
		if addr != nil {
			if source, ok := netip.AddrFromSlice(addr.IP); ok {
				return responder.ReplyFrom(bytes, netip.AddrPortFrom(source.Unmap(), uint16(addr.Port)))
			}
		}
		return responder.Reply(bytes)
	}
	t.handler.NewPacket(toV2RayDestination(flow.Source, v2rayNet.Network_UDP), toV2RayDestination(flow.Destination, v2rayNet.Network_UDP), data, writeBack)
}
