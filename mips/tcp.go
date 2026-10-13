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
	"context"

	"github.com/metacubex/mipstack"

	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
)

func (t *Tun) forwardTCP(request *mipstack.TCPForwarderRequest) {
	flow := request.Flow()
	if t.dropFlow(flow.Source.Addr(), flow.Destination.Addr()) {
		_ = request.Drop()
		return
	}
	conn, err := request.Accept(context.Background())
	if err != nil {
		return
	}
	go t.handler.NewConnection(toV2RayDestination(flow.Source, v2rayNet.Network_TCP), toV2RayDestination(flow.Destination, v2rayNet.Network_TCP), conn)
}
