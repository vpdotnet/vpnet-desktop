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

import QtQuick 2.9
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import "../../../../javascript/app.js" as App
import "../../../../javascript/util.js" as Util
import "../../../common"
import "../../../core"
import "../../../daemon"
import "../../../theme"
import "../../../helpers"
import PIA.NativeAcc 1.0 as NativeAcc

MovableModule {
  id: ipModule
  moduleKey: 'ip'

  implicitHeight: 80

  //: Screen reader annotation for the tile displaying the IP addresses.
  tileName: uiTr("IP tile")
  NativeAcc.Group.name: tileName

  ConnStateHelper {
    id: connState
  }

  property real vpnElementsOpacityTarget: {
    switch(connState.connectionState) {
    default:
    case connState.stateDisconnecting:
    case connState.stateDisconnected:
    case connState.stateConnecting:
      return 0.3
    case connState.stateConnected:
      return 1
    }
  }
  property real vpnElementsOpacity: vpnElementsOpacityTarget
  Behavior on vpnElementsOpacity {
    NumberAnimation {
      easing.type: Easing.InOutQuad
      duration: 300
    }
  }

  LabelText {
    id: ipLabel
    text: uiTr("IP")
    color: Theme.dashboard.moduleTitleColor
    font.pixelSize: Theme.dashboard.moduleLabelTextPx
    x: 20
    y: 20
  }

  CopiableValueText {
    id: currentTextLabel

    copiable: !!Daemon.state.externalIp
    text: Daemon.state.externalIp || "---"
    label: ipLabel.text
    color: {
      if(connState.connectionState === connState.stateDisconnected ||
         connState.connectionState === connState.stateDisconnecting)
        return Theme.dashboard.moduleTitleColor
      return Theme.dashboard.moduleTextColor
    }
    font.pixelSize: Theme.dashboard.moduleValueTextPx
    x: 20
    y: 40
  }

  LabelText {
    id: vpnIpLabel
    text: uiTr("VPN IP")
    color: Theme.dashboard.moduleTitleColor
    font.pixelSize: Theme.dashboard.moduleLabelTextPx
    x: 170
    y: 20
    opacity: vpnElementsOpacity
  }

  CopiableValueText {
    id: vpnIpValue
    copiable: !!Daemon.state.externalVpnIp

    text: Daemon.state.externalVpnIp || "---"
    label: vpnIpLabel.text
    color: Theme.dashboard.moduleTextColor
    font.pixelSize: Theme.dashboard.moduleValueTextPx
    x: 170
    y: 40
    opacity: vpnElementsOpacity
  }

  Image {
    id: arrow
    source: Theme.dashboard.moduleRightArrowImage
    width: 25
    height: 25
    y: 25
    x: 130
    rtlMirror: true
    opacity: vpnElementsOpacity
  }

}
