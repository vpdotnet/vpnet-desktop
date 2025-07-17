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

#include "linux_firewall.h"
#include "linux_fwmark.h"
#include "linux_routing.h"
#include "rt_tables_initializer.h"
#include <kapps_core/src/newexec.h>
#include <kapps_core/src/ipaddress.h>
#include "proc_tracker.h"
#include <iostream>

namespace kapps { namespace net {

namespace
{
    // for convenience
    using IPVersion = IpTablesFirewall::IPVersion;

    // Define the location of the rt_tables files
    const std::string etcRoutingLocation{"/etc/iproute2/rt_tables"};
    const std::string libRoutingLocation{"/usr/lib/iproute2/rt_tables"};
    // Used by iproute2 versions >= 6.7.0
    const std::string shareRoutingLocation{"/usr/share/iproute2/rt_tables"};
}

LinuxFirewall::LinuxFirewall(FirewallConfig config)
    : _config{std::move(config)},
      _executableDir{_config.executableDir}
{
    _pFilter.emplace(_config);

    // Setup cgroup object for retrieving and configuring cgroup information for split tunnel
    _pCgroup.emplace(_config);

    // Add our custom routing tables to the rt_tables file.
    // We do this here rather than in the installer as there is some complexity involved.
    RtTablesInitializer rtTablesInitializer{
        _config.brandInfo.code,
        {etcRoutingLocation, {shareRoutingLocation, libRoutingLocation}}
    };
    rtTablesInitializer.install();

    _pFilter->install();
}

LinuxFirewall::~LinuxFirewall()
{
    assert(_pFilter);   // Class invariant
    _pFilter->uninstall();
    KAPPS_CORE_INFO() << "Linux firewall shutdown complete";
}

void LinuxFirewall::applyRules(const FirewallParams &params)
{
    KAPPS_CORE_INFO() << "Inside applyrules";
    assert(_pFilter);
    assert(_pCgroup);

    if(!_pFilter->isInstalled())
        _pFilter->install();

    const auto &netScan = params.netScan;

    _pFilter->ensureRootAnchorPriority();

    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, "999.allowLoopback", params.allowLoopback);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, "100.blockAll", params.blockAll);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, "200.allowVPN", params.allowVPN);
    // Allow bypass apps to override KS only when disconnected -
    // if we were to allow this rule when connected as well (which just allows a bypass app to do what it wants)
    // then it'll override our split tunnel DNS leak protection rules (possibly
    // allowing DNS on all interfaces) which is not what we want.
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::IPv4, "230.allowBypassApps", params.blockAll && !params.isConnected);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::IPv6, "250.blockIPv6", params.blockIPv6);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, "290.allowDHCP", params.allowDHCP);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::IPv6, "299.allowIPv6Prefix", netScan.hasIpv6() && params.allowLAN);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, "300.allowLAN", params.allowLAN);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, "305.allowSubnets", !params.bypassIpv4Subnets.empty() || !params.bypassIpv6Subnets.empty());
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, "310.blockDNS", params.blockDNS);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::IPv4, "320.allowDNS", params.hasConnected);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::IPv4, "100.protectLoopback", true);

    // Nat table
    // Split DNS NAT rules disabled since split tunnel has been removed
    _pFilter->setAnchorEnabled(TableEnum::Nat, IPVersion::IPv4, ("80.splitDNS"), false);
    _pFilter->setAnchorEnabled(TableEnum::Nat, IPVersion::IPv4, ("90.snatDNS"), false);
    _pFilter->setAnchorEnabled(TableEnum::Nat, IPVersion::IPv4, ("80.fwdSplitDNS"), false);
    _pFilter->setAnchorEnabled(TableEnum::Nat, IPVersion::IPv4, ("90.fwdSnatDNS"), false);

    // block VpnOnly packets when the VPN is not connected
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, ("340.blockVpnOnly"), params.tunnelDeviceName.empty());
    // Split tunnel removed, so no bypass apps
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, ("350.allowHnsd"), params.allowResolver);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, ("350.cgAllowHnsd"), false);

    // Allow VPNet Wireguard packets when VPNet is allowed.  These come from the
    // kernel when using the kernel module method, so they aren't covered by the
    // allowVPNet rule, which is based on GID.
    // This isn't needed for OpenVPN or userspace WG, but it doesn't do any
    // harm.
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, ("390.allowWg"), params.allowVPNet);
    _pFilter->setAnchorEnabled(TableEnum::Filter, IPVersion::Both, ("400.allowVPNet"), params.allowVPNet);

    // Mark forwarded packets in all cases (so we can block when KS is on)
    _pFilter->setAnchorEnabled(TableEnum::Mangle, IPVersion::Both, ("100.tagFwd"), true);

   bool enableVpnTunOnly = updateVpnTunOnlyAnchor(params.hasConnected,  params.tunnelDeviceName, params.tunnelDeviceLocalAddress);
   _pFilter->setAnchorEnabled(TableEnum::Raw, IPVersion::IPv4, "100.vpnTunOnly", enableVpnTunOnly);

    // Update dynamic rules that depend on info such as the adapter name and/or DNS servers

    updateRules(params);

    updateForwardedRoutes(params);

    // Split tunnel feature removed
}

// Split tunnel feature removed

void LinuxFirewall::updateRules(const FirewallParams &params)
{
    const std::string &adapterName = params.tunnelDeviceName;
    KAPPS_CORE_INFO() << "VPN interface:" << adapterName;
    const std::string &ipAddress6 = params.netScan.ipAddress6();

    // These rules only depend on the adapter name
    if(adapterName != _adapterName)
    {
        if(adapterName.empty())
        {
            // Don't know the adapter name, wipe out the rules
            KAPPS_CORE_INFO() << "Clearing allowVPN and allowHnsd rules, adapter name is not known";
            _pFilter->replaceAnchor(TableEnum::Filter, IPVersion::Both, ("200.allowVPN"), {});
            _pFilter->replaceAnchor(TableEnum::Filter, IPVersion::Both, ("350.allowHnsd"), {});
        }
        else
        {
            _pFilter->replaceAnchor(TableEnum::Filter, IPVersion::Both, ("200.allowVPN"), { qs::format("-o % -j ACCEPT", adapterName) });
            _pFilter->replaceAnchor(TableEnum::Filter, IPVersion::Both, ("350.allowHnsd"), {
                qs::format("-m owner --gid-owner % -o % -p tcp --match multiport --dports 53,13038 -j ACCEPT", _pFilter->hnsdGroupName(), adapterName),
                qs::format("-m owner --gid-owner % -o % -p udp --match multiport --dports 53,13038 -j ACCEPT", _pFilter->hnsdGroupName(), adapterName),
                qs::format("-m owner --gid-owner % -j REJECT", _pFilter->hnsdGroupName()),
            });
        }
    }

    if(ipAddress6 != _ipAddress6)
    {
        if(ipAddress6.empty())
        {
            KAPPS_CORE_INFO() << "Clearing out allowIPv6Prefix rule, no global IPv6 addresses found";
            _pFilter->replaceAnchor(TableEnum::Filter, IPVersion::IPv6, ("299.allowIPv6Prefix"), {});
        }
        else
        {
            // First 64 bits is the IPv6 Network Prefix. This prefix is shared by all IPv6 hosts on the LAN,
            // so whitelisting it allows those hosts to communicate
            _pFilter->replaceAnchor(TableEnum::Filter, IPVersion::IPv6, ("299.allowIPv6Prefix"),
                          { qs::format("-d %/64 -j ACCEPT", ipAddress6)});
        }
    }

    updateBypassSubnets(IPVersion::IPv4, params.bypassIpv4Subnets, _bypassIpv4Subnets);
    updateBypassSubnets(IPVersion::IPv6, params.bypassIpv6Subnets, _bypassIpv6Subnets);

    // Manage DNS for forwarded packets
    SplitDNSInfo::SplitDNSType routedDns = SplitDNSInfo::SplitDNSType::VpnOnly;

    // Split tunnel removed, always use VPN DNS for routed packets
    SplitDNSInfo routedDnsInfo = SplitDNSInfo::infoFor(params, routedDns, *_pCgroup);

    // Since we can't control where routed DNS is addressed, always create rules
    // to force it to the DNS server specified.
    if(routedDnsInfo != _routedDnsInfo)
    {
        if(routedDnsInfo.isValid())
        {
            KAPPS_CORE_INFO() << "Sending routed DNS to DNS server"
                << routedDnsInfo.dnsServer() << "via source IP" << routedDnsInfo.sourceIp();
            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, "90.fwdSnatDNS", {
                qs::format("-p udp --match mark --mark % -m udp --dport 53 -j SNAT --to-source %",
                    _pFilter->fwmark().forwardedPacketTag(), routedDnsInfo.sourceIp()),
                qs::format("-p tcp --match mark --mark % -m tcp --dport 53 -j SNAT --to-source %",
                    _pFilter->fwmark().forwardedPacketTag(), routedDnsInfo.sourceIp())
                });

            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, "80.fwdSplitDNS", {
                qs::format("-p udp --match mark --mark % -m udp --dport 53 -j DNAT --to-destination %:53",
                    _pFilter->fwmark().forwardedPacketTag(), routedDnsInfo.dnsServer()),
                qs::format("-p tcp --match mark --mark % -m tcp --dport 53 -j DNAT --to-destination %:53",
                    _pFilter->fwmark().forwardedPacketTag(), routedDnsInfo.dnsServer()),
                });

        }
        else
        {
            KAPPS_CORE_INFO() << qs::format("Not creating routed packet DNS rules, received empty value dnsServer: %, sourceIp: %", routedDnsInfo.dnsServer(), routedDnsInfo.sourceIp());
            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, "90.fwdSnatDNS",
                          {});

            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, "80.fwdSplitDNS",
                          {});
        }

        _routedDnsInfo = routedDnsInfo;
    }

    // Split tunnel DNS has been removed
    SplitDNSInfo appDnsInfo;

    // To implement split tunnel DNS, create SNAT/DNAT rules to force UDP/TCP 53
    // packets to the proper DNS server.
    //
    // appDnsInfo tells us which type of apps must be forced - whichever rule is
    // the opposite of the "all other apps" behavior.
    if(appDnsInfo != _appDnsInfo)
    {
        if(appDnsInfo.isValid())
        {
            KAPPS_CORE_INFO() << qs::format("Updating split tunnel DNS due to network change: dnsServer: %, cgroupId %, sourceIp %",
                appDnsInfo.dnsServer(), appDnsInfo.cGroupId(), appDnsInfo.sourceIp());
            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, ("90.snatDNS"), {
                qs::format("-p udp -m cgroup --cgroup % -m udp --dport 53 -j SNAT --to-source %", appDnsInfo.cGroupId(), appDnsInfo.sourceIp()),
                qs::format("-p tcp -m cgroup --cgroup % -m tcp --dport 53 -j SNAT --to-source %", appDnsInfo.cGroupId(), appDnsInfo.sourceIp()),
            });

            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, ("80.splitDNS"), {
                qs::format("-p udp -m cgroup --cgroup % -m udp --dport 53 -j DNAT --to-destination %:53", appDnsInfo.cGroupId(), appDnsInfo.dnsServer()),
                qs::format("-p tcp -m cgroup --cgroup % -m tcp --dport 53 -j DNAT --to-destination %:53", appDnsInfo.cGroupId(), appDnsInfo.dnsServer()),
            });

        }
        else
        {
            KAPPS_CORE_INFO() << qs::format("Clear split tunnel DNS rules, don't have all information: dnsServer: %, cgroupId %, sourceIp %",
                appDnsInfo.dnsServer(), appDnsInfo.cGroupId(), appDnsInfo.sourceIp());
            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, "90.snatDNS", {});

            _pFilter->replaceAnchor(TableEnum::Nat, IPVersion::IPv4, "80.splitDNS", {});
        }
    }

    // DNS rules depend on both adapters and DNS servers, update if either has
    // changed
    if(params.effectiveDnsServers != _dnsServers || adapterName != _adapterName || appDnsInfo != _appDnsInfo)
    {
        // If the adapter name isn't set, getDNSRules() returns an empty list
        std::vector<std::string> effectiveDnsRules = getDNSRules(adapterName, params.effectiveDnsServers);

        std::vector<std::string> ruleList;

        // Split tunnel has been removed, no special DNS handling needed
        if(false)
        {
            // This code is disabled as split tunnel has been removed
            std::string forcedDnsServer;
            std::string forcedDnsCgroup;

            if(false)
            {
                // Permit forced apps to reach the forced DNS.
                if(!forcedDnsServer.empty())
                {
                    ruleList.push_back(qs::format("-p udp -m cgroup --cgroup % -m udp --dport 53 -d % -j ACCEPT", forcedDnsCgroup, forcedDnsServer));
                    ruleList.push_back(qs::format("-p tcp -m cgroup --cgroup % -m tcp --dport 53 -d % -j ACCEPT", forcedDnsCgroup, forcedDnsServer));
                }
                // Block forced apps from any other DNS.
                // Doing this prevents a forced app re-using a port/route used
                // by a different type of app
                ruleList.push_back(qs::format("-p udp -m cgroup --cgroup % -m udp --dport 53 -j REJECT", forcedDnsCgroup));
                ruleList.push_back(qs::format("-p tcp -m cgroup --cgroup % -m tcp --dport 53 -j REJECT", forcedDnsCgroup));

                // Reject non-forced apps from using forced DNS (prevents a
                // different type of app re-using a port/route from a forced app)
                if(!forcedDnsServer.empty())
                {
                    // Use "not the forced cgroup" instead of "the other cgroup"
                    // - When the VPN has the default route, VPN-only apps
                    //   aren't placed into a cgroup.
                    // - This also includes "default behavior" apps - although
                    //   no leaks have been observed this way, this is most
                    //   robust.
                    ruleList.push_back(qs::format("-p udp -m cgroup ! --cgroup % -m udp --dport 53 -d % -j REJECT", forcedDnsCgroup, forcedDnsServer));
                    ruleList.push_back(qs::format("-p tcp -m cgroup ! --cgroup % -m tcp --dport 53 -d % -j REJECT", forcedDnsCgroup, forcedDnsServer));
                }
            }
        }

        // Permit apps that get through all of the cgroup filters (above) to
        // reach the configured DNS.
        //
        // This must occur after cgroup filtering when ST DNS is enabled.
        // Otherwise, when not using systemd-resolved, this could defeat the
        // leak protection above.
        for(auto &dnsRule : effectiveDnsRules)
            ruleList.push_back(std::move(dnsRule));

        // Re-allow localhost DNS now we've plugged the leaks.
        // localhost DNS is important for systemd which uses a 127.0.0.53 DNS proxy
        // for all DNS traffic.
        ruleList.push_back("-o lo+ -p udp -m udp --dport 53 -j ACCEPT");
        ruleList.push_back("-o lo+ -p tcp -m tcp --dport 53 -j ACCEPT");

        _pFilter->replaceAnchor(TableEnum::Filter, IPVersion::IPv4, "320.allowDNS", ruleList);
    }

    // Split tunnel removed, no need to enable localhost routing
    disableRouteLocalNet();

    _appDnsInfo = appDnsInfo;
    _adapterName = adapterName;
    _ipAddress6 = ipAddress6;
    _dnsServers = params.effectiveDnsServers;
}

bool LinuxFirewall::updateVpnTunOnlyAnchor(bool hasConnected, std::string tunnelDeviceName, std::string tunnelDeviceLocalAddress)
{
    if(hasConnected)
    {
        if(tunnelDeviceName.empty() || tunnelDeviceLocalAddress.empty())
        {
            KAPPS_CORE_WARNING() << "Not enabling 100.vpnTunOnly rule, do not have tunnel device config:"
                << tunnelDeviceName << "-" << tunnelDeviceLocalAddress;
            return false;
        }

        KAPPS_CORE_INFO() << "Enabling 100.vpnTunOnly rule for tun device"
            << tunnelDeviceName << "-" << tunnelDeviceLocalAddress;
        _pFilter->replaceAnchor(TableEnum::Raw,
            IPVersion::IPv4,
            "100.vpnTunOnly",
            {
                qs::format("! -i % -d % -m addrtype ! --src-type LOCAL -j DROP", tunnelDeviceName, tunnelDeviceLocalAddress),
            });
        return true;
    }

    return false;
}

void LinuxFirewall::updateForwardedRoutes(const FirewallParams &params)
{
    // Split tunnel removed - routed traffic always goes through VPN
    // Create the VPN route for this traffic once connected
    if(params.hasConnected)
        kapps::core::Exec::bash(qs::format("ip route replace default dev % table %", params.tunnelDeviceName, _pFilter->routing().forwardedTable()));
    // Not connected
    else
        kapps::core::Exec::bash(qs::format("ip route delete default table %", _pFilter->routing().forwardedTable()));

    // Add blackhole fall-back route to block all forwarded traffic if killswitch is on (and disconnected)
    if(params.leakProtectionEnabled)
        kapps::core::Exec::bash(qs::format("ip route replace blackhole default metric 32000 table %", _pFilter->routing().forwardedTable()));
    else
        kapps::core::Exec::bash(qs::format("ip route delete blackhole default metric 32000 table %", _pFilter->routing().forwardedTable()));

    // Blackhole IPv6 for forwarded connections too, for IPv6 leak protection and killswitch
    if(params.blockIPv6)
        kapps::core::Exec::bash(qs::format("ip -6 route replace blackhole default metric 32000 table %", _pFilter->routing().forwardedTable()));
    else
        kapps::core::Exec::bash(qs::format("ip -6 route delete blackhole default metric 32000 table %", _pFilter->routing().forwardedTable()));
}


std::vector<std::string> LinuxFirewall::getDNSRules(const std::string &vpnAdapterName, const std::vector<std::string>& servers)
{
    if(vpnAdapterName.empty())
    {
        KAPPS_CORE_INFO() << "Adapter name not set, not applying DNS firewall rules";
        return {};
    }

    std::vector<std::string> result;
    for(const std::string& server : servers)
    {
        // If this is a local DNS server, allow it on any adapter; we don't
        // know which adapter would be used.  If it's a non-local DNS server,
        // restrict it to the VPN interface.
        //
        // Invalid addresses (if they occur somehow) are treated as non-local by
        // default.  If the address is unparseable, Ipv4Address is set to
        // 0.0.0.0, which is non-local.
        std::string restrictAdapter{};
        if(!core::Ipv4Address{server}.isLocalDNS())
            restrictAdapter = qs::format("-o %", vpnAdapterName);
        result.push_back(qs::format("% -d % -p udp --dport 53 -j ACCEPT", restrictAdapter, server));
        result.push_back(qs::format("% -d % -p tcp --dport 53 -j ACCEPT", restrictAdapter, server));
    }
    return result;
}

void LinuxFirewall::enableRouteLocalNet()
{
    if(!_routeLocalNet.empty())
        return; // Already enabled and stored the prior value

    _routeLocalNet = kapps::core::Exec::bashWithOutput("sysctl -n 'net.ipv4.conf.all.route_localnet'");
    if(!_routeLocalNet.empty())
    {
        if(std::stoul(_routeLocalNet) != 1)
        {
            KAPPS_CORE_INFO() << "Storing old net.ipv4.conf.all.route_localnet value:" << _routeLocalNet;
            KAPPS_CORE_INFO() << "Setting route_localnet to 1";
            kapps::core::Exec::bash("sysctl -w 'net.ipv4.conf.all.route_localnet=1'");
        }
        else
        {
            KAPPS_CORE_INFO() << "route_localnet already 1; nothing to do!";
        }
    }
    else
    {
        KAPPS_CORE_WARNING() << "Unable to store old net.ipv4.conf.all.route_localnet value";
    }
}

void LinuxFirewall::disableRouteLocalNet()
{
    if(_routeLocalNet.empty())
        return;

    if(std::stoul(_routeLocalNet) == 1)
    {
        KAPPS_CORE_INFO() << "Previous route_localnet was" << _routeLocalNet
            << "- nothing to restore";
    }
    else if(!_routeLocalNet.empty())
    {
        KAPPS_CORE_INFO() << "Restoring route_localnet to: " << _routeLocalNet;
        kapps::core::Exec::bash(qs::format("sysctl -w 'net.ipv4.conf.all.route_localnet=%'", _routeLocalNet));
    }
    _routeLocalNet = "";
}

void LinuxFirewall::updateBypassSubnets(IPVersion ipVersion, const std::set<std::string> &bypassSubnets, std::set<std::string> &oldBypassSubnets)
{
    if(bypassSubnets != oldBypassSubnets)
    {
        if(bypassSubnets.empty())
        {
            std::string versionString = (ipVersion == IPVersion::IPv6 ? "IPv6" : "IPv4");
            KAPPS_CORE_INFO() << "Clearing out" << versionString << "allowSubnets rule, no subnets found";
            _pFilter->replaceAnchor(TableEnum::Filter, ipVersion, ("305.allowSubnets"), {});

            // Clear out the rules for tagging bypass subnet packets
            if(ipVersion == IPVersion::IPv4)
            {
                KAPPS_CORE_INFO() << "Clearing out 90.tagSubnets";
                _pFilter->replaceAnchor(TableEnum::Mangle, ipVersion, ("90.tagSubnets"), {});
            }
            KAPPS_CORE_INFO() << "Clearing out 200.tagFwdSubnets";
            _pFilter->replaceAnchor(TableEnum::Mangle, ipVersion, ("200.tagFwdSubnets"), {});
        }
        else
        {
            std::vector<std::string> subnetAcceptRules;
            for(const auto &subnet : bypassSubnets)
                subnetAcceptRules.push_back(qs::format("-d % -j ACCEPT", subnet));


            // If there's any IPv6 addresses then we also need to whitelist link-local and broadcast
            // as these address ranges are needed for IPv6 Neighbor Discovery.
            if(ipVersion == IPVersion::IPv6)
            {
                subnetAcceptRules.push_back(qs::format("-d fe80::/10 -j ACCEPT"));
                subnetAcceptRules.push_back(qs::format("-d ff00::/8 -j ACCEPT"));
            }

            _pFilter->replaceAnchor(TableEnum::Filter, ipVersion, "305.allowSubnets", subnetAcceptRules);

            std::vector<std::string> subnetMarkRules;
            for(const auto &subnet : bypassSubnets)
            {
                subnetMarkRules.push_back(qs::format("-d % -j MARK --set-mark %", subnet,
                    _pFilter->fwmark().excludePacketTag()));
            }
            // We tag all packets heading towards a bypass subnet. This tag (excludePacketTag) is
            // used by our routing policies to route traffic outside the VPN.
            if(ipVersion == IPVersion::IPv4)
            {
                KAPPS_CORE_INFO() << "Setting 90.tagSubnets";

                _pFilter->replaceAnchor(TableEnum::Mangle, ipVersion, "90.tagSubnets", subnetMarkRules);
            }

            // For routed connections to bypassed subnets, apply the
            // bypass mark so they will always be routed to the original
            // gateway, regardless of the routed connection setting.
            _pFilter->replaceAnchor(TableEnum::Mangle, ipVersion, "200.tagFwdSubnets", subnetMarkRules);
        }
    }
    oldBypassSubnets = bypassSubnets;
}

std::string SplitDNSInfo::existingDNS(const std::vector<uint32_t> &existingDNSServers)
{
    if(existingDNSServers.empty())
        return {};
    else
        return core::Ipv4Address{existingDNSServers.front()}.toString();
}

SplitDNSInfo SplitDNSInfo::infoFor(const FirewallParams &params, SplitDNSType splitType, const CGroupIds &cgroup)
{
    std::string dnsServer, cGroupId, sourceIp;

    if(splitType == SplitDNSType::Bypass)
    {
        dnsServer = existingDNS(params.existingDNSServers);
        cGroupId = cgroup.bypassId();
        sourceIp = params.netScan.ipAddress();
    }
    else
    {
        auto servers = params.effectiveDnsServers;
        dnsServer = servers.empty() ? std::string{} : servers.front();
        cGroupId = cgroup.vpnOnlyId();
        sourceIp = params.tunnelDeviceLocalAddress;
    }

    // Deal with loopback dns server special case - if dnsServer is loopback then sourceIp must be too
    if(core::Ipv4Address{dnsServer}.isLoopback())
        sourceIp = "127.0.0.1";

    return {dnsServer, cGroupId, sourceIp};
}

bool SplitDNSInfo::isValid() const
{
    return !_dnsServer.empty() && !_cGroupId.empty() && !_sourceIp.empty();
}

}}
