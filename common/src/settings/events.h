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

#ifndef SETTINGS_EVENTS_H
#define SETTINGS_EVENTS_H

#include "../common.h"
#include "../json.h"
#include "version.h"
#include "product.h"

// Event properties class (no longer used, but referenced in other files)
class COMMON_EXPORT EventProperties : public NativeJsonObject
{
    Q_OBJECT
private:
    static const QString &semanticVersionQstr();
    static const QString &userAgentQstr();

public:
    EventProperties() = default;
    EventProperties(const EventProperties &other) { *this = other; }
    EventProperties &operator=(const EventProperties &other)
    {
        user_agent(other.user_agent());
        platform(other.platform());
        version(other.version());
        prerelease(other.prerelease());
        vpn_protocol(other.vpn_protocol());
        connection_source(other.connection_source());
        time_to_connect(other.time_to_connect());
        return *this;
    }
    bool operator==(const EventProperties &other) const
    {
        return user_agent() == other.user_agent() &&
            platform() == other.platform() &&
            version() == other.version() &&
            prerelease() == other.prerelease() &&
            vpn_protocol() == other.vpn_protocol() &&
            time_to_connect() == other.time_to_connect() &&
            connection_source() == other.connection_source();
    }
    bool operator!=(const EventProperties &other) const {return !(*this == other);}

public:
    // User agent; client information
    JsonField(QString, user_agent, userAgentQstr())
    JsonField(QString, platform, PIA_PLATFORM_NAME)
    JsonField(QString, version, semanticVersionQstr())
    JsonField(bool, prerelease, PIA_VERSION_IS_PRERELEASE)
    // The VPN protocol being used
    JsonField(QString, vpn_protocol, {}, {"OpenVPN", "WireGuard"})
    // The source of the connection:
    // - "Manual" - The user directly initiated this connection (e.g. by
    //   clicking the Connect button).  CLI "connect" is also interpreted
    //   as manual.
    // - "Automatic" - The connection was initiated automatically (e.g. by
    //   ending Snooze or an automation rule.)
    JsonField(QString, connection_source, {}, {"Manual", "Automatic"})
    JsonField(Optional<float>, time_to_connect, nullptr)
};

// ServiceQualityEvent class has been removed

#endif
