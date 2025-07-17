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

#pragma once
#include <kapps_net/net.h>
#include <kapps_core/core.h>
#include "originalnetworkscan.h"
#include <string>
#include <set>
#include <vector>
#include <memory>

#if defined(KAPPS_CORE_OS_WINDOWS)
#include "win/appidkey.h"
#endif

namespace kapps { namespace net {

// Descriptor for a set of firewall rules to be applied.
//
struct KAPPS_NET_EXPORT FirewallParams
{
    // These parameters are specified by VPNConnection (some are passed through
    // from the VPNMethod)

    // VPN network interface information
    std::string tunnelDeviceName;
    std::string tunnelDeviceLocalAddress;
    std::string tunnelDeviceRemoteAddress;

    // Linux only
    // Whether routed packets (i.e Docker) should go over VPN or not
    // if set to false then routed packets bypass VPN
    bool routedPacketsOnVPN;

    // The following flags indicate which general rulesets are needed. Note that
    // this is after some sanity filtering, i.e. an allow rule may be listed
    // as not needed if there were no block rules preceding it. The rulesets
    // should be thought of as in last-match order.
    bool leakProtectionEnabled; // Apply leak protection (on for KS=always, or for KS=auto when connected)
    bool blockAll;      // Block all traffic by default
    bool allowVPN;      // Exempt traffic through VPN tunnel
    bool allowDHCP;     // Exempt DHCP traffic
    bool blockIPv6;     // Block all IPv6 traffic
    bool allowLAN;      // Exempt LAN traffic, including IPv6 LAN traffic
    bool blockDNS;      // Block all DNS traffic except specified DNS servers
    bool allowVPNet;    // Exempt VPNet executables
    bool allowLoopback; // Exempt loopback traffic
    bool allowResolver; // Exempt local DNS resolver traffic

    // Whether we are connected to the VPN right now.  Note that this differs
    // from 'hasConnected'.
    bool isConnected;
    // Have we connected to the VPN since it was enabled?  (Some rules are only
    // activated once we successfully connect, but remain active even if we lose
    // the connection while reconnecting.)
    bool hasConnected;
    // Whether the default route has or will be set to the VPN (false when not
    // connected or connecting).
    bool setDefaultRoute;

    // Split tunnel feature removed
    // bool bypassDefaultApps; - removed
    // bool enableSplitTunnel; - removed
    OriginalNetworkScan netScan;
    // bool splitTunnelDnsEnabled; - removed

    // Mtu of the tunnel interface
    int mtu;

    // DNS servers
    std::vector<std::string> effectiveDnsServers;

#if defined(KAPPS_CORE_OS_POSIX)
    // Split tunnel feature removed
    // std::vector<std::string> excludeApps; - removed
    // std::vector<std::string> vpnOnlyApps; - removed
#elif defined(KAPPS_CORE_OS_WINDOWS)
    // Split tunnel feature removed
    // AppIdSet excludeApps; - removed
    // AppIdSet vpnOnlyApps; - removed
#endif

    std::set<std::string> bypassIpv4Subnets; // IPv4 subnets to bypass VPN
    std::set<std::string> bypassIpv6Subnets; // IPv6 subnets to bypass VPN
    // macos only - indentifies the primary interface
    std::string macosPrimaryServiceKey;

    // The DNS servers prior to connecting
    std::vector<uint32_t> existingDNSServers;
#if defined(KAPPS_CORE_OS_MACOS)
    // Split tunnel feature removed
    // bool transparentProxyLogEnabled; - removed
#endif
};

}}
