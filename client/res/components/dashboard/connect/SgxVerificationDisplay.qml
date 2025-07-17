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
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.3
import "../../daemon"
import "../../theme"
import "../../common"
import "../../helpers"
import PIA.NativeHelpers 1.0
import PIA.NativeAcc 1.0 as NativeAcc

Item {
  id: sgxDisplay
  
  // Only visible when using WireGuard and not disconnected
  visible: (Daemon.state.connectionState === "Connecting" || 
            Daemon.state.connectionState === "Connected") &&
           (Daemon.displayConnectionConfig.method === 'wireguard' || 
            Daemon.state.connectedConfig.method === 'wireguard')
  
  height: visible ? contentLayout.height : 0
  
  ConnStateHelper {
    id: connState
  }
  
  // Check if we have MRENCLAVE value (connected with SGX)
  readonly property bool hasMrEnclave: Daemon.state.connectedMrEnclave && 
                                       Daemon.state.connectedMrEnclave.length > 0
  readonly property bool isConnecting: connState.connectionState === connState.stateConnecting
  readonly property bool isConnected: connState.connectionState === connState.stateConnected
  
  // Get first 16 characters of MRENCLAVE
  readonly property string truncatedMrEnclave: hasMrEnclave ? 
    Daemon.state.connectedMrEnclave.substring(0, 16) : ""
  
  // Animation properties
  property string animatedMrEnclave: ""
  property int currentDigitIndex: 0
  
  // Timer for hash animation
  Timer {
    id: hashAnimationTimer
    interval: 20
    repeat: true
    running: false
    
    onTriggered: {
      if (currentDigitIndex < truncatedMrEnclave.length) {
        animatedMrEnclave += truncatedMrEnclave[currentDigitIndex]
        currentDigitIndex++
      } else {
        // Animation complete
        running = false
      }
    }
  }
  
  // Start animation when we get a new hash
  onTruncatedMrEnclaveChanged: {
    if (truncatedMrEnclave && isConnected) {
      // Reset animation
      animatedMrEnclave = ""
      currentDigitIndex = 0
      // Start timer
      hashAnimationTimer.running = true
    }
  }
  
  // Also start animation when transitioning from connecting to connected
  onIsConnectedChanged: {
    if (isConnected && truncatedMrEnclave) {
      // Reset animation
      animatedMrEnclave = ""
      currentDigitIndex = 0
      // Start timer
      hashAnimationTimer.running = true
    }
  }
  
  
  ColumnLayout {
    id: contentLayout
    anchors.horizontalCenter: parent.horizontalCenter
    spacing: 2
    
    // First line: status text with icon
    RowLayout {
      Layout.alignment: Qt.AlignHCenter
      spacing: 6
      
      Text {
        text: {
          if (isConnecting) {
            return uiTr("Verifying...")
          } else if (isConnected) {
            // Always show "Verified Privacy™" when connected with WireGuard
            // even if we don't have MRENCLAVE yet
            return uiTr("Verified Privacy™")
          }
          return ""
        }
        
        color: isConnecting ? Theme.dashboard.textDisabledColor : Theme.dashboard.textColor
        font.pixelSize: 14
        visible: text !== ""
      }
      
      // Green checkmark icon when verified
      Image {
        visible: isConnected
        source: Theme.imagePath + "/changelog/checkmark-valid.png"
        width: 16
        height: 16
        sourceSize.width: 16
        sourceSize.height: 16
        smooth: true
      }
    }
    
    // Second line: MRENCLAVE hash with info icon (only when connected)
    RowLayout {
      visible: isConnected && hasMrEnclave
      Layout.alignment: Qt.AlignHCenter
      spacing: 4
      
      Text {
        text: animatedMrEnclave
        color: "#1DA1F2" // Twitter blue
        font.pixelSize: 12
        font.family: "monospace"
      }
      
      // Info icon
      Text {
        text: "ⓘ"
        color: "#1DA1F2"
        font.pixelSize: 14
      }
    }
    
  }
  
  // Clickable area for the entire component
  ButtonArea {
    anchors.fill: contentLayout
    visible: isConnected && hasMrEnclave
    cursorShape: Qt.PointingHandCursor
    
    //: Screen reader annotation for the SGX verification display
    name: uiTr("SGX enclave verification")
    description: uiTr("View SGX enclave details in browser")
    
    onClicked: {
      if (hasMrEnclave) {
        // Open browser with the full MRENCLAVE hash
        Qt.openUrlExternally("https://vp.net/enclave/" + Daemon.state.connectedMrEnclave)
      }
    }
  }
}