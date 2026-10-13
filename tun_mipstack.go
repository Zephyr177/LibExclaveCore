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

package libexclavecore

import (
	"github.com/exclavenetwork/libexclavecore/mips"
)

// newMipsTun runs the mihomo IP stack over the packet device shared with the
// other userspace stacks.
func newMipsTun(config *TunConfig, t *Tun2ray, discardIPv6Func func() bool) (*mips.Tun, error) {
	device, tunOptions, err := newSingTunDevice(config, t)
	if err != nil {
		return nil, err
	}
	mipsTun, err := mips.New(mips.Options{
		Device:      device,
		MTU:         tunOptions.MTU,
		Addr4:       t.addr4,
		Addr6:       t.addr6,
		EnableIPv6:  config.EnableIPv6,
		DiscardICMP: config.DiscardICMP,
		DiscardIPv6: discardIPv6Func,
		Handler:     t,
	})
	if err != nil {
		_ = device.Close()
		return nil, err
	}
	return mipsTun, nil
}
