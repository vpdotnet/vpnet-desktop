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
#include <kapps_core/src/util.h>
#include <kapps_net/net.h>
#include <kapps_core/core.h>
#include <kapps_core/logger.h>
#include <unordered_map>
#include "../firewallparams.h"
#include "../routemanager.h"
#include "../subnetbypass.h"
#include "../firewall.h"
#include "wfp_firewall.h"
#include "../originalnetworkscan.h"
#include <string>
#include <vector>
#include <map>

namespace kapps { namespace net {

        struct FirewallFilters
        {
            std::vector<WfpFilterObject> permitProduct;
            WfpFilterObject permitAdapter[2];
            WfpFilterObject permitLocalhost[2];
            WfpFilterObject permitDHCP[2];
            WfpFilterObject permitLAN[10];
            WfpFilterObject blockDNS[2];
            WfpFilterObject permitInjectedDns;
            WfpFilterObject ipInbound;
            WfpFilterObject ipOutbound;
            WfpFilterObject permitDNS[2];
            WfpFilterObject blockAll[2];
            std::vector<WfpFilterObject> permitResolvers;
            std::vector<WfpFilterObject> blockResolvers;

            // This is not strictly a filter, but it can in nearly all respects be treated the same way
            // so we store it here for simplicity and so we can re-use the filter-related code
            WfpCalloutObject splitCalloutBind;
            WfpCalloutObject splitCalloutConnect;
            WfpCalloutObject splitCalloutFlowEstablished;
            WfpCalloutObject splitCalloutConnectAuth;
            WfpCalloutObject splitCalloutIpInbound;
            WfpCalloutObject splitCalloutIpOutbound;

            WfpProviderContextObject providerContextKey;
            WfpProviderContextObject vpnOnlyProviderContextKey;

        };

    // Split tunnel feature removed - structures removed


        class WinFirewall : public PlatformFirewall
        {
        private:

        public:
            WinFirewall(FirewallConfig config);
            virtual ~WinFirewall() override;

        public:
            void applyRules(const FirewallParams &params) override;

        protected:
            // Split tunnel feature removed

        private:
            // Split tunnel feature removed - areAppsUnchanged method removed

            void updateAllBypassSubnetFilters(const FirewallParams &params);
            void updateBypassSubnetFilters(const std::set<std::string> &subnets, std::set<std::string> &oldSubnets,
                                   std::vector<WfpFilterObject> &subnetBypassFilters, FWP_IP_VERSION ipVersion);
            // Split tunnel feature removed - app filter methods removed
            // Split tunnel feature removed

        private:
            const FirewallConfig _config{};
            kapps::net::SubnetBypass _subnetBypass;
            std::unique_ptr<FirewallEngine> _firewall{};

            // App IDs for resolver executables, needed to bind these programs
            // to the VPN when the default behavior is to bypass
            AppIdSet _resolverAppIds;

            // Inputs to reapplySplitTunnelFirewall() - the last set of inputs used is
            // stored so we know when to recreate the firewall rules.
            // Split tunnel feature removed - _lastSplitParams removed

            UINT64 _filterAdapterLuid{0}; // LUID of the TAP adapter used in some rules
            std::string _dnsServers[2]; // Last DNS servers that we applied
            FirewallFilters _filters;

            // Split tunnel feature removed - app maps removed

            std::set<std::string> _bypassIpv4Subnets;
            std::set<std::string> _bypassIpv6Subnets;

            std::vector<WfpFilterObject> _subnetBypassFilters4;
            std::vector<WfpFilterObject> _subnetBypassFilters6;
        };
    }}
