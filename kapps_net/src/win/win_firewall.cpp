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

#include "win_firewall.h"
#include "wfp_firewall.h"
#include "win_routemanager.h"
#include <kapps_core/src/win/win_error.h>
#include <thread>
#include <tuple>
#include <kapps_core/src/logger.h>
#include <kapps_core/src/ipaddress.h>
#include <kapps_core/src/newexec.h>
#include <WinDNS.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace kapps { namespace net {

namespace
{
    void logFilter(const char* filterName, int currentState, bool enableCondition, bool invalidateCondition = false)
    {
        if (enableCondition ? currentState != 1 || invalidateCondition : currentState != 0)
        {
            KAPPS_CORE_INFO().nospace() << filterName << ": "
                << (currentState == 1 ? "ON" : currentState == 0 ? "OFF" : "MIXED")
                << " -> " << (enableCondition ? "ON" : "OFF");
        }
        else
        {
            KAPPS_CORE_INFO().nospace() << filterName << ": "
                << (enableCondition ? "ON" : "OFF");
        }
    }

    void logFilter(const char* filterName, const GUID& filterVariable, bool enableCondition, bool invalidateCondition = false)
    {
        logFilter(filterName, filterVariable == zeroGuid ? 0 : 1, enableCondition, invalidateCondition);
    }

    template<class FilterObjType, class FilterVarIterT>
    void logFilter(const char *filterName, FilterVarIterT itFiltersBegin,
        FilterVarIterT itFiltersEnd, bool enableCondition,
        bool invalidateCondition = false)
    {
        if(itFiltersBegin == itFiltersEnd)
        {
            // No filter variables - assume it was inactive
            logFilter(filterName, 0, enableCondition, invalidateCondition);
            return;
        }

        // Get the state of the first filter
        int state = (*itFiltersBegin == zeroGuid) ? 0 : 1;
        ++itFiltersBegin;
        // Check for the "mixed" state if any filter is in the opposite state
        while(itFiltersBegin != itFiltersEnd)
        {
            int s = (*itFiltersBegin == zeroGuid) ? 0 : 1;
            if (s != state)
            {
                state = 2;
                break;
            }
            ++itFiltersBegin;
        }
        logFilter(filterName, state, enableCondition, invalidateCondition);
    }

    template<class FilterObjType, size_t N>
    void logFilter(const char* filterName, const FilterObjType (&filterVariables)[N], bool enableCondition, bool invalidateCondition = false)
    {
        // MSVC has trouble deducing the iterator type in this call for some
        // reason, tell it explicitly
        using FilterVarIterT = decltype(std::begin(filterVariables));
        logFilter<FilterObjType, FilterVarIterT>(filterName,
            std::begin(filterVariables), std::end(filterVariables),
            enableCondition, invalidateCondition);
    }
    template<class FilterObjType>
    void logFilter(const char* filterName,
        const std::vector<FilterObjType> &filterVariables, bool enableCondition,
        bool invalidateCondition = false)
    {
        // MSVC has trouble deducing the iterator type in this call for some
        // reason, tell it explicitly
        using FilterVarIterT = decltype(filterVariables.begin());
        logFilter<FilterObjType, FilterVarIterT>(filterName,
            filterVariables.begin(), filterVariables.end(),
            enableCondition, invalidateCondition);
    }

    std::vector<core::Ipv4Address> findExistingDNS(const std::vector<core::Ipv4Address> &vpnetDNSServers)
    {
        std::vector<core::Ipv4Address> newDNSServers;

        // What we'd really like to do here is get the DNS servers for the primary
        // network interface.  Unfortunately, there is no API to do that, and even
        // parsing `netsh interface ip show dnsservers` won't work since that relies
        // on the DNSCache service (which VPNet must stop to implement split tunnel
        // DNS).
        //
        // The best we can do is to get all DNS servers, which may include VPNet's,
        // but the preexisting servers will still be there.  Then filter out VPNet's
        // servers.
        //
        // If no DNS servers remain, then assume that the existing DNS servers were
        // the same as VPNet's - use VPNet's DNS servers for bypass apps too.
        //
        // There are a few ways that this can be incorrect if there were no existing
        // DNS servers, or the existing DNS servers were a subset of VPNet's, etc.
        // Given the assumption that alternate DNS servers configured on the same
        // adapter are equivalent, it will behave reasonably, generally just adding
        // or removing some equivalent DNS servers.
        //
        // The only way this can really significantly fail is if the user has
        // multiple physical adapters, with different DNS servers configured on
        // each, and where the primary adapter's DNS servers are the same as VPNet's.
        // In this case, we would incorrectly treat the secondary adapter's servers
        // as the preexisting DNS, and likely use them on the primary adapter.

        std::aligned_storage_t<1024, alignof(IP4_ARRAY)> dnsAddrBuf;
        DWORD dnsBufLen = sizeof(dnsAddrBuf);
        DNS_STATUS status = DnsQueryConfig(DnsConfigDnsServerList, 0,
                                        NULL, NULL, &dnsAddrBuf, &dnsBufLen);
        if(status == 0) // Success
        {
            const IP4_ARRAY &dnsServers = *reinterpret_cast<const IP4_ARRAY*>(&dnsAddrBuf);
            newDNSServers.reserve(dnsServers.AddrCount);
            KAPPS_CORE_INFO() << "Got" << dnsServers.AddrCount
                << "existing DNS servers";
            for(DWORD i=0; i<dnsServers.AddrCount; ++i)
            {
                core::Ipv4Address dnsServerAddr{ntohl(dnsServers.AddrArray[i])};
                // Check if this was one of ours.  We only apply up to 2 DNS
                // servers, so a linear search through the vector is fine.
                bool setByVPNet = std::find(vpnetDNSServers.begin(), vpnetDNSServers.end(),
                                        dnsServerAddr) != vpnetDNSServers.end();
                KAPPS_CORE_INFO() << " -" << i << "-" << dnsServerAddr
                    << (setByVPNet ? "(ours)" : "");
                if(!setByVPNet)
                    newDNSServers.push_back(dnsServerAddr);
            }

            // If no DNS servers remain, then the preexisting DNS servers were
            // likely the same as VPNet's - assume they were.
            if(newDNSServers.empty())
            {
                KAPPS_CORE_INFO() << "All DNS servers appear to be ours, assuming preexisting servers were the same";
                newDNSServers = vpnetDNSServers;
            }
        }
        else
        {
            KAPPS_CORE_WARNING() << "Could not get existing DNS servers - error" << status;
        }

        return newDNSServers;
    }

}

WinFirewall::WinFirewall(FirewallConfig config)
    : _config{std::move(config)},
      _subnetBypass{std::make_unique<WinRouteManager>()},
      _firewall{new FirewallEngine{_config.brandInfo}},
      _filterAdapterLuid{0},
      // Ensure our filters are zero-initialized - since
      // it's an aggregate with simple members this wont happen by default.
      _filters{}
{
    // Product and resolver executables can't be changed after the firewall is
    // created, size our GUID vectors appropriately now
    _filters.permitProduct.resize(_config.productExecutables.size());
    _filters.permitResolvers.resize(_config.resolverExecutables.size());
    _filters.blockResolvers.resize(_config.resolverExecutables.size());

    for(const auto &exe : _config.resolverExecutables)
    {
        std::shared_ptr<const AppIdKey> pResolverId{new AppIdKey{exe}};
        if(*pResolverId)
            _resolverAppIds.insert(std::move(pResolverId));
        else
        {
            KAPPS_CORE_WARNING() << "Failed to find app ID for resolver"
                << exe;
        }
    }

    if(!_firewall->open() || !_firewall->installProvider())
    {
        KAPPS_CORE_ERROR() << "Unable to initialize WFP firewall";
        _firewall.reset();
    }
    else
    {
        _firewall->removeAll();
    }
}

WinFirewall::~WinFirewall()
{
#define deactivateFilter(filterVariable, removeCondition) \
    do { \
        /* Remove existing rule if necessary */ \
        if ((removeCondition) && filterVariable != zeroGuid) \
        { \
            if (!_firewall->remove(filterVariable)) { \
                KAPPS_CORE_WARNING() << "Failed to remove WFP filter" << #filterVariable; \
            } \
            filterVariable = {zeroGuid}; \
        } \
    } \
    while(false)
#define activateFilter(filterVariable, addCondition, ...) \
    do { \
        /* Add new rule if necessary */ \
        if ((addCondition) && filterVariable == zeroGuid) \
        { \
            if ((filterVariable = _firewall->add(__VA_ARGS__)) == zeroGuid) { \
                /* TODO: report error to product */ \
                KAPPS_CORE_WARNING() << "Firewall rule failed:" << #filterVariable; \
                /*reportError(Error(HERE, Error::FirewallRuleFailed, { std::stringLiteral(#filterVariable) }));*/ \
            } \
        } \
    } \
    while(false)
#define updateFilter(filterVariable, removeCondition, addCondition, ...) \
    do { \
        deactivateFilter(_filters.filterVariable, removeCondition); \
        activateFilter(_filters.filterVariable, addCondition, __VA_ARGS__); \
    } while(false)
#define updateBooleanFilter(filterVariable, enableCondition, ...) \
    do { \
        const bool enable = (enableCondition); \
        updateFilter(filterVariable, !enable, enable, __VA_ARGS__); \
    } while(false)
#define updateBooleanInvalidateFilter(filterVariable, enableCondition, invalidateCondition, ...) \
    do { \
        const bool enable = (enableCondition); \
        const bool disable = !enable || (invalidateCondition); \
        updateFilter(filterVariable, disable, enable, __VA_ARGS__); \
    } while(false)
#define filterActive(filterVariable) (_filters.filterVariable != zeroGuid)

    if (_firewall)
    {
        KAPPS_CORE_INFO() << "Cleaning up WFP objects";

        if (_filters.ipInbound != zeroGuid)
        {
            KAPPS_CORE_INFO() << "deactivate IpInbound object";
            deactivateFilter(_filters.ipInbound, true);
        }

        if (_filters.splitCalloutIpInbound != zeroGuid)
        {
            KAPPS_CORE_INFO() << "deactivate IpInbound callout object";
            deactivateFilter(_filters.splitCalloutIpInbound, true);
        }

        if (_filters.ipOutbound != zeroGuid)
        {
            KAPPS_CORE_INFO() << "deactivate IpOutbound object";
            deactivateFilter(_filters.ipOutbound, true);
        }

        if (_filters.splitCalloutIpOutbound != zeroGuid)
        {
            KAPPS_CORE_INFO() << "deactivate IpOutbound callout object";
            deactivateFilter(_filters.splitCalloutIpOutbound, true);
        }

        _firewall->removeAll();
        _firewall->uninstallProvider();
        _firewall->checkLeakedObjects();
    }
    else
        KAPPS_CORE_INFO() << "Firewall was not initialized, nothing to clean up";

    KAPPS_CORE_INFO() << "Windows firewall shutdown complete";
}

void WinFirewall::applyRules(const FirewallParams &params)
{
    if(!_firewall)
        return;

    FirewallTransaction tx(_firewall.get());

#define deactivateFilter(filterVariable, removeCondition) \
    do { \
        /* Remove existing rule if necessary */ \
        if ((removeCondition) && filterVariable != zeroGuid) \
        { \
            if (!_firewall->remove(filterVariable)) { \
                KAPPS_CORE_WARNING() << "Failed to remove WFP filter" << #filterVariable; \
            } \
            filterVariable = {zeroGuid}; \
        } \
    } \
    while(false)
#define activateFilter(filterVariable, addCondition, ...) \
    do { \
        /* Add new rule if necessary */ \
        if ((addCondition) && filterVariable == zeroGuid) \
        { \
            if ((filterVariable = _firewall->add(__VA_ARGS__)) == zeroGuid) { \
                /* TODO: report error to product */ \
                KAPPS_CORE_WARNING() << "Firewall rule failed:" << #filterVariable; \
                /*reportError(Error(HERE, Error::FirewallRuleFailed, { std::string(#filterVariable) }));*/ \
            } \
        } \
    } \
    while(false)
#define updateFilter(filterVariable, removeCondition, addCondition, ...) \
    do { \
        deactivateFilter(_filters.filterVariable, removeCondition); \
        activateFilter(_filters.filterVariable, addCondition, __VA_ARGS__); \
    } while(false)
#define updateBooleanFilter(filterVariable, enableCondition, ...) \
    do { \
        const bool enable = (enableCondition); \
        updateFilter(filterVariable, !enable, enable, __VA_ARGS__); \
    } while(false)
#define updateBooleanInvalidateFilter(filterVariable, enableCondition, invalidateCondition, ...) \
    do { \
        const bool enable = (enableCondition); \
        const bool disable = !enable || (invalidateCondition); \
        updateFilter(filterVariable, disable, enable, __VA_ARGS__); \
    } while(false)
#define filterActive(filterVariable) (_filters.filterVariable != zeroGuid)

    // Firewall rules, listed in order of ascending priority (as if the last
    // matching rule applies, but note that it is the priority argument that
    // actually determines precedence).

    // As a bit of an exception to the normal firewall rule logic, the WFP
    // rules handle the blockIPv6 rule by changing the priority of the IPv6
    // part of the killswitch rule instead of having a dedicated IPv6 block.

    // Block all other traffic when killswitch is enabled. If blockIPv6 is
    // true, block IPv6 regardless of killswitch state.
    logFilter("blockAll(IPv4)", _filters.blockAll[0], params.blockAll);
    updateBooleanFilter(blockAll[0], params.blockAll,                     EverythingFilter<FWP_ACTION_BLOCK, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(0));
    logFilter("blockAll(IPv6)", _filters.blockAll[1], params.blockAll || params.blockIPv6);
    updateBooleanFilter(blockAll[1], params.blockAll || params.blockIPv6, EverythingFilter<FWP_ACTION_BLOCK, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(params.blockIPv6 ? 4 : 0));

    // Exempt traffic going over the VPN adapter.  This is the TAP adapter for
    // OpenVPN, or the WinTUN adapter for Wireguard.

    UINT64 luid{};
    if(!params.tunnelDeviceName.empty())
    {
        try
        {
            luid = std::stoull(params.tunnelDeviceName);
        }
        catch(const std::exception &ex)
        {
            KAPPS_CORE_WARNING() << "Unable to parse tunnel device name"
                << params.tunnelDeviceName << "-" << ex.what();
            // Leave luid == 0, handled in filter logic below
        }
    }

    logFilter("allowVPN", _filters.permitAdapter, luid && params.allowVPN, luid != _filterAdapterLuid);
    updateBooleanInvalidateFilter(permitAdapter[0], luid && params.allowVPN, luid != _filterAdapterLuid, InterfaceFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(luid, 2));
    updateBooleanInvalidateFilter(permitAdapter[1], luid && params.allowVPN, luid != _filterAdapterLuid, InterfaceFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(luid, 2));
    _filterAdapterLuid = luid;
    // Note: This is where the IPv6 block rule is ordered if blockIPv6 is true.

    // Exempt DHCP traffic.
    logFilter("allowDHCP", _filters.permitDHCP, params.allowDHCP);
    updateBooleanFilter(permitDHCP[0], params.allowDHCP, DHCPFilter<FWP_ACTION_PERMIT, FWP_IP_VERSION_V4>(6));
    updateBooleanFilter(permitDHCP[1], params.allowDHCP, DHCPFilter<FWP_ACTION_PERMIT, FWP_IP_VERSION_V6>(6));

    // Permit LAN traffic depending on settings
    logFilter("allowLAN", _filters.permitLAN, params.allowLAN);
    updateBooleanFilter(permitLAN[0], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{192,168,0,0}, 16, 8));
    updateBooleanFilter(permitLAN[1], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{172,16,0,0}, 12, 8));
    updateBooleanFilter(permitLAN[2], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{10,0,0,0}, 8, 8));
    updateBooleanFilter(permitLAN[3], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{224,0,0,0}, 4, 8));
    updateBooleanFilter(permitLAN[4], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{169,254,0,0}, 16, 8));
    updateBooleanFilter(permitLAN[5], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{255,255,255,255}, 32, 8));
    updateBooleanFilter(permitLAN[6], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(core::Ipv6Address{0xfc00}, 7, 8));
    updateBooleanFilter(permitLAN[7], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(core::Ipv6Address{0xfe80}, 10, 8));
    updateBooleanFilter(permitLAN[8], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(core::Ipv6Address{0xff00}, 8, 8));
    // Permit the IPv6 global Network Prefix - this allows on-link IPv6 hosts to communicate using their global IPs
    // which is more common in practice than link-local
    updateBooleanFilter(permitLAN[9], params.netScan.hasIpv6() && params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(
            // First 64 bits of a global IPv6 IP is the Network Prefix.
            core::Ipv6Address{params.netScan.ipAddress6()}, 64, 8));

    // Poke holes in firewall for the bypass subnets for Ipv4 and Ipv6
    updateAllBypassSubnetFilters(params);

    // Add rules to block non-VPNet DNS servers if connected and DNS leak protection is enabled
    logFilter("blockDNS", _filters.blockDNS, params.blockDNS);
    updateBooleanFilter(blockDNS[0], params.blockDNS, DNSFilter<FWP_ACTION_BLOCK, FWP_IP_VERSION_V4>(10));
    updateBooleanFilter(blockDNS[1], params.blockDNS, DNSFilter<FWP_ACTION_BLOCK, FWP_IP_VERSION_V6>(10));

    std::string dnsServers[2];
    if(params.effectiveDnsServers.size() >= 1)
        dnsServers[0] = params.effectiveDnsServers[0];
    if(params.effectiveDnsServers.size() >= 2)
        dnsServers[1] = params.effectiveDnsServers[1];
    logFilter("allowDNS(1)", _filters.permitDNS[0], params.blockDNS && !dnsServers[0].empty(), _dnsServers[0] != dnsServers[0]);
    updateBooleanInvalidateFilter(permitDNS[0], params.blockDNS && !dnsServers[0].empty(), _dnsServers[0] != dnsServers[0], IPAddressFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{dnsServers[0]}, 14));
    _dnsServers[0] = dnsServers[0];
    logFilter("allowDNS(2)", _filters.permitDNS[1], params.blockDNS && !dnsServers[1].empty(), _dnsServers[1] != dnsServers[1]);
    updateBooleanInvalidateFilter(permitDNS[1], params.blockDNS && !dnsServers[1].empty(), _dnsServers[1] != dnsServers[1], IPAddressFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(core::Ipv4Address{dnsServers[1]}, 14));
    _dnsServers[1] = dnsServers[1];

    // Always permit traffic from product executables.  This allows us to fetch
    // metadata, download updates, submit debug reports, etc., even when the
    // kill switch is active.
    logFilter("allowVPNet", _filters.permitProduct, params.allowVPNet);
    // Class invariant - product executables can't be changed.
    // Note that it's also important that the _content_ of productExecutables is
    // immutable as well as the length; that's not checked here.
    assert(_filters.permitProduct.size() == _config.productExecutables.size());
    for(std::size_t i=0; i<_config.productExecutables.size(); ++i)
    {
        const std::wstring &exe{_config.productExecutables[i]};
        updateBooleanFilter(permitProduct[i], params.allowVPNet && !exe.empty(),
            ApplicationFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND,
                FWP_IP_VERSION_V4>{exe, 15});
    }

    // Local resolver related filters
    logFilter("allowResolver (block everything)", _filters.blockResolvers, luid && params.allowResolver, luid != _filterAdapterLuid);
    logFilter("allowResolver (tunnel traffic)", _filters.permitResolvers, luid && params.allowResolver, luid != _filterAdapterLuid);
    // Class invariant - resolver executables can't be changed.
    // Just like the product executables, it's also relevant that the actual
    // resolver paths can't be changed too.
    assert(_filters.blockResolvers.size() == _config.resolverExecutables.size());
    assert(_filters.permitResolvers.size() == _config.resolverExecutables.size());
    for(std::size_t i=0; i<_config.resolverExecutables.size(); ++i)
    {
        const std::wstring &exe{_config.resolverExecutables[i]};
        // (1) First we block everything coming from the resolver processes
        updateBooleanInvalidateFilter(blockResolvers[i],
            luid && params.allowResolver && !exe.empty(),
            luid != _filterAdapterLuid,
            ApplicationFilter<FWP_ACTION_BLOCK, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>{exe, 14});
        // (2) Next we poke a hole in this block but only allow data that goes across the tunnel
        updateBooleanInvalidateFilter(permitResolvers[i],
            luid && params.allowResolver && !exe.empty(),
            luid != _filterAdapterLuid,
            ApplicationFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>{exe, 15,
                Condition<FWP_UINT64>{FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL, &luid},
                Condition<FWP_UINT16>{FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, 53},
        // OR'ing of conditions is done automatically when you have 2 or more
        // consecutive conditions of the same fieldId. 13038 is the Handshake
        // control port
                Condition<FWP_UINT16>{FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, 13038}
            });
    }

    // Always permit loopback traffic, including IPv6.
    logFilter("allowLoopback", _filters.permitLocalhost, params.allowLoopback);
    updateBooleanFilter(permitLocalhost[0], params.allowLoopback, LocalhostFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(15));
    updateBooleanFilter(permitLocalhost[1], params.allowLoopback, LocalhostFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(15));

    // Split tunnel feature removed

    // Split tunnel feature removed

    // Split tunnel feature removed

    // Split tunnel feature removed

    // Update subnet bypass routes
    _subnetBypass.updateRoutes(params);

    tx.commit();
}

void WinFirewall::updateAllBypassSubnetFilters(const FirewallParams &params)
{
    // Process subnet bypass rules without split tunnel check
    if(params.bypassIpv4Subnets != _bypassIpv4Subnets)
        updateBypassSubnetFilters(params.bypassIpv4Subnets, _bypassIpv4Subnets, _subnetBypassFilters4, FWP_IP_VERSION_V4);

    if(params.bypassIpv6Subnets != _bypassIpv6Subnets)
        updateBypassSubnetFilters(params.bypassIpv6Subnets, _bypassIpv6Subnets, _subnetBypassFilters6, FWP_IP_VERSION_V6);

    // Clean up existing subnet filters if needed
    if(params.bypassIpv4Subnets.empty() && !_bypassIpv4Subnets.empty())
        updateBypassSubnetFilters({}, _bypassIpv4Subnets, _subnetBypassFilters4, FWP_IP_VERSION_V4);

    if(params.bypassIpv6Subnets.empty() && !_bypassIpv6Subnets.empty())
        updateBypassSubnetFilters({}, _bypassIpv6Subnets, _subnetBypassFilters6, FWP_IP_VERSION_V6);
}

void WinFirewall::updateBypassSubnetFilters(const std::set<std::string> &subnets, std::set<std::string> &oldSubnets, std::vector<WfpFilterObject> &subnetBypassFilters, FWP_IP_VERSION ipVersion)
{
    for (auto &filter : subnetBypassFilters)
        deactivateFilter(filter, true);

    // If we have any IPv6 subnets we need to also whitelist IPv6 link-local and broadcast ranges
    // required by IPv6 Neighbor Discovery
    auto adjustedSubnets = subnets;
    if(ipVersion == FWP_IP_VERSION_V6 && !subnets.empty())
    {
        adjustedSubnets.emplace("fe80::/10");
        adjustedSubnets.emplace("ff00::/8");
    }

    subnetBypassFilters.resize(adjustedSubnets.size());

    int index{0};
    for(auto it = adjustedSubnets.begin(); it != adjustedSubnets.end(); ++it, ++index)
    {
        if(ipVersion == FWP_IP_VERSION_V6)
        {
            KAPPS_CORE_INFO() << "Creating Subnet ipv6 rule" << *it;
            activateFilter(subnetBypassFilters[index], true,
                IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(*it, 10));
        }
        else
        {
            KAPPS_CORE_INFO() << "Creating Subnet ipv4 rule" << *it;
            activateFilter(subnetBypassFilters[index], true,
                IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(*it, 10));
        }
    }

    // Update the bypass subnets
    oldSubnets = subnets;
}

// Split tunnel feature removed

}}
