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

pragma Singleton
import QtQuick 2.0
// Split tunnel feature removed

// These are Settings-related messages used in multiple places (so they're only
// translated once).  Messages that are used in just one place can be left
// in-source.
QtObject {
  // Title for successful reinstallation messages
  readonly property string titleReinstallSuccessful: uiTranslate("HelpPage", "Reinstall successful")
  // Title for failed reinstallation messages
  readonly property string titleReinstallError: uiTranslate("HelpPage", "Reinstall error")
  // Split tunnel feature removed

  // Messages indicating that the VPN connection can not be established
  readonly property var vpnSupportErrors: {
    //: Message for Linux indicating that iptables is missing
    "iptables_missing": uiTranslate("ClientNotifications", "Iptables is not installed.")
  }

  readonly property string requiresOpenVpnMessage: uiTr("This feature requires OpenVPN.")

  // Labels for connection settings - used on Connection page and in Connection
  // tile
  readonly property string connectionTypeSetting: uiTranslate("ConnectionPage", "Transport")
  readonly property string remotePortSetting: uiTranslate("ConnectionPage", "Remote Port")
  readonly property string dataEncryptionSetting: uiTranslate("ConnectionPage", "Data Encryption")
  readonly property string dataAuthenticationSetting: uiTranslate("ConnectionPage", "Data Authentication")
  readonly property string handshakeSetting: uiTranslate("ConnectionPage", "Handshake")
  readonly property string defaultRemotePort: uiTranslate("ConnectionPage", "Default")

  readonly property string mtuSetting: uiTr("MTU")
  readonly property string mtuSettingAuto: uiTranslate("mtu_setting", "Auto")
  readonly property string mtuSettingLargePackets: uiTranslate("mtu_setting", "Large Packets")
  readonly property string mtuSettingSmallPackets: uiTranslate("mtu_setting", "Small Packets")
  readonly property string mtuSettingDescription: [
    uiTr("Determines the maximum packet size allowed through the tunnel."),
    uiTr("Auto: Detect automatically, best for most connections"),
    uiTr("Large Packets: Most efficient if the connection is reliable"),
    uiTr("Small Packets: Less efficient but best on unreliable connections")
  ].join("\n\u2022\xA0\xA0")
  
  // Split tunnel feature removed
}
