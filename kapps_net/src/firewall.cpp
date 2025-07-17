// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include "firewall.h"
#include <kapps_core/src/logger.h>

#if defined(KAPPS_CORE_OS_WINDOWS)
#include "win/win_firewall.h"
#elif defined(KAPPS_CORE_OS_MACOS)
#include "mac/mac_firewall.h"
// Split tunnel feature removed
#elif defined(KAPPS_CORE_OS_LINUX)
#include "linux/linux_firewall.h"
#endif

namespace kapps { namespace net {

Firewall::Firewall(FirewallConfig config)
{
#if defined(KAPPS_CORE_FAMILY_DESKTOP)
    using PlatformFirewallType =
    #if defined(KAPPS_CORE_OS_WINDOWS)
        WinFirewall
    #elif defined(KAPPS_CORE_OS_MACOS)
        MacFirewall
    #elif defined(KAPPS_CORE_OS_LINUX)
        LinuxFirewall
    #endif
    ;

    _pPlatformFirewall.reset(new PlatformFirewallType{std::move(config)});
#else
    // TODO - Don't provide Firewall APIs at all on non-desktop platforms
    throw std::runtime_error{"kapps::net::Firewall not available on this platform"};
#endif
}

void Firewall::applyRules(const FirewallParams &params)
{
    assert(_pPlatformFirewall); // Class invariant
    _pPlatformFirewall->applyRules(params);
}

#if defined(KAPPS_CORE_OS_MACOS)
void Firewall::aboutToConnectToVpn()
{
    assert(_pPlatformFirewall); // Class invariant
    _pPlatformFirewall->aboutToConnectToVpn();
}
#endif

}}
