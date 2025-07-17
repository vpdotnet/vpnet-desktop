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

import QtQuick 2.15
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import "../../../javascript/app.js" as App
import "../../daemon"
import "../../theme"
import "../../common"
import "../../core"
import "../../errors"
import PIA.Error 1.0
import PIA.FlexValidator 1.0
import PIA.BrandHelper 1.0
import PIA.NativeHelpers 1.0

FocusScope {
  // Whether we display an error, and if we do, what error it is.
  readonly property var errors: {
    'none': 0,
    'auth': 1,
    'rate': 2, // Rate limited
    'api': 3,  // Error reaching API, etc. (user's creds might be correct)
    'unknown': 4,
    'email_sent': 5,
    'expired': 6  // The user's subscription has expired
  }
  property int shownError: errors.none
  property int emailError: errors.none
  property int tokenError: errors.none
  property bool hasValidInput: {
    if (mode === modes.login) {
      return loginInput.text.length > 0 && passwordInput.text.length > 0
    } else if (mode === modes.email) {
      return emailInput.text.length > 0 && emailInput.acceptableInput
    } else if (mode === modes.token) {
      return tokenInput.text.length > 0
    }
    return false
  }
  property bool loginInProgress: false
  property bool emailRequestInProgress: false
  property bool tokenValidationInProgress: false
  readonly property int pageHeight: 400
  readonly property int maxPageHeight: pageHeight
  readonly property bool emailLoginFeatureEnabled: true

  property real retryAfterTime: 0
  property string lastEmail: "" // Store the last email used to request a token

  // The current time which can be updated by a timer
  property real currentTime: 0

  // A timer that always updates the current time once every second
  // because we cannot have the current time automatically updated
  Timer {
    onTriggered: {
      currentTime = Date.now();
    }
    repeat: true
    interval: 1000
    running: retryAfterTime > 0 && retryAfterTime + 2000 > currentTime
  }

  // The login page can be in one of multiple distinct modes:
  //
  // - login: For a regular email/password login.
  // - email: Form to allow user to request email login link
  // - token: Form to input the token received via email
  readonly property var modes: {
    'login': 0,
    'email': 1,
    'token': 2,
  }
  property int mode: 0

  function resetLoginPage (newMode) {
    newMode = newMode || modes.login;
    shownError = errors.none
    emailError = errors.none
    tokenError = errors.none
    loginInProgress = false
    emailRequestInProgress = false
    tokenValidationInProgress = false
    emailInput.text = ""
    tokenInput.text = ""
    lastEmail = ""
    mode = newMode
  }
  
  function validateToken() {
    if(tokenInput.text.length > 0 && !tokenValidationInProgress) {
      tokenValidationInProgress = true
      tokenError = errors.none
      
      console.log('Validating token for email:', lastEmail);
      console.log('Token length:', tokenInput.text.length);
      
      // Add a small delay to ensure UI state is updated before proceeding
      Qt.callLater(function() {
        console.log('Calling setToken with token...');
        
        Daemon.setToken(tokenInput.text, function(error) {
          console.log('Token validation callback received');
          tokenValidationInProgress = false
          
          if (error) {
            console.error('Token validation failed. Error code:', error.code, 'Error message:', error.errorString);
            
            // Display a more useful error message based on the error
            switch(error.code) {
              case NativeError.ApiUnauthorizedError:
                console.error('API unauthorized error - invalid token');
                tokenError = errors.auth
                break
              case NativeError.ApiRateLimitedError:
                console.error('API rate limited error');
                tokenError = errors.rate
                break
              case NativeError.ApiNetworkError:
                console.error('API network error - cannot reach server');
                tokenError = errors.api
                break
              default:
                console.error('Unknown error with code:', error.code);
                tokenError = errors.unknown
                break
            }
          } else {
            console.log('Token validation succeeded. User now logged in.');
            // Check Daemon.account.loggedIn to verify login state
            console.log('Daemon.account.loggedIn:', Daemon.account.loggedIn);
            
            if (Daemon.account.loggedIn) {
              resetLoginPage(modes.login)
            } else {
              console.error('Token validation succeeded but account is not logged in!');
              tokenError = errors.unknown
            }
          }
        });
      });
    }
  }

  function requestEmailLogin () {
    if(emailInput.text.length > 0 && !emailRequestInProgress) {
      emailRequestInProgress = true
      emailError = errors.none

      console.log('Requesting email login for:', emailInput.text);
      
      Daemon.emailLogin(emailInput.text, function(error) {
        emailRequestInProgress = false
        if (error) {
          console.error('Email token request failed. Error code:', error.code, 'Error message:', error.message);
          
          // Display a more useful error message based on the error
          switch(error.code) {
          case NativeError.ApiUnauthorizedError:
            emailError = errors.auth
            break
          case NativeError.ApiRateLimitedError:
            emailError = errors.rate
            break
          case NativeError.ApiNetworkError:
            emailError = errors.api
            break
          default:
            emailError = errors.unknown
            break
          }
        } else {
          console.log('Email login request succeeded. Check your email for the login token.');
          lastEmail = emailInput.text
          emailError = errors.none
          mode = modes.token
        }
      });
    }
  }

  function login() {
    // The user can press Enter even if the credentials haven't been entered;
    // log in only if the credentials are set.
    if(hasValidInput && !loginInProgress) {
      loginInProgress = true
      shownError = errors.none
      retryAfterTime = 0
      currentTime = 0

      // We trim off any errant newlines from password (usually introduced by copy/paste)
      Daemon.login(loginInput.text, passwordInput.text.replace(/\n+$/, ''), function(error) {
        if (error) {
          // Failure - creds were not valid (or we couldn't communicate
          // with the daemon, etc.)
          loginInProgress = false
          switch(error.code) {
          case NativeError.ApiUnauthorizedError:
            shownError = errors.auth
            break
          case NativeError.ApiRateLimitedError:
            if(error.retryAfterTime > 0) {
              currentTime = Date.now()
              retryAfterTime = error.retryAfterTime
            }
            shownError = errors.rate
            break
          case NativeError.ApiPaymentRequiredError:
            // Api error Payment Required (http status 402)
            // is used to indicate an account subscription has expired
            shownError = errors.expired
            // Change the displayed page to the upgrade page
            stateStack.showUpgradePage()
            break
          default:
            shownError = errors.api
            break
          }
          console.warn('Login failed:', error);
        }
      });
    }
  }

  // Contains both the normal 'login' page and the 'upgrade required' page (if the user's account expired)
  StackLayout {
    id: stateStack
    readonly property int loginPageIndex: 0
    readonly property int upgradePageIndex: 1
    property int activeIndex: loginPageIndex
    anchors.fill: parent
    currentIndex: activeIndex

    // Default page
    function showLoginPage() {
      stateStack.activeIndex = loginPageIndex
    }

    // Shown when the user's subscription expires
    function showUpgradePage() {
      stateStack.activeIndex = upgradePageIndex
    }

    // The "login" page (everything contained in this Rectangle)
    Rectangle {
      color: "transparent"
      clip: true
      Item {
        id: mapContainer
        width: parent.width
        height: Math.min(parent.height * 0.4, 150)
        anchors.top: parent.top

        LocationMap {
          id: mapImage
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.centerIn: parent
          height: Math.min(parent.height - 14, 130)
          width: {
            console.info("map size: " + 2*height + "x" + height)
            return 2*height
          }
          mapOpacity: Theme.login.mapOpacity
          markerInnerRadius: 3.5
          markerOuterRadius: 6.5
          location: Daemon.state.vpnLocations.nextLocation
        }
      }

      Item {
        id: loginContent
        anchors.centerIn: parent
        width: parent.width
        implicitHeight: Math.max(usernameModeContent.height, emailLoginItem.height, tokenLoginItem.height)
        anchors.verticalCenterOffset: 20

        // Username/password login
        Item {
          id: usernameModeContent
          width: parent.width
          height: lb.y + lb.height
          visible: mode === modes.login
          Text {
            color: Theme.login.errorTextColor
            horizontalAlignment: Text.AlignHCenter
            text: {
              switch(shownError) {
              case errors.auth:
                return uiTr("Invalid login")
              case errors.rate:
                return uiTr("Too many login attempts.") + "\n" + Messages.tryAgainMessage(Math.ceil((retryAfterTime - currentTime) / 1000))
              case errors.api:
                return uiTr("Can't reach the server")
              case errors.expired:
                return uiTr("Your subscription has expired")
              default:
                return ""
              }
            }
            anchors.bottom: loginInput.top
            anchors.bottomMargin: -6
            anchors.horizontalCenter: parent.horizontalCenter
            font.pixelSize: Theme.login.errorTextPx
            visible: shownError !== errors.none
          }

          FlexValidator {
            id: loginValidator
            regularExpression: /.*/
            function fixInput(input) { return input.trim() }
          }

          LoginText {
            id: loginInput
            errorState: shownError !== errors.none
            anchors.horizontalCenter: parent.horizontalCenter
            width: 260
            anchors.top: parent.top
            anchors.topMargin: 16
            placeholderText: uiTr("Username")
            validator: loginValidator
            onAccepted: login()
            errorTipText: {
              if(loginInput.text.startsWith('x')) {
                return uiTr("Use your normal username beginning with 'p'.")
              }
              return ""
            }
          }

          LoginText {
            id: passwordInput
            errorState: shownError !== errors.none
            width: 260
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: loginInput.bottom
            anchors.topMargin: 8
            placeholderText: uiTr("Password")
            onAccepted: login()
            masked: true
          }

          LoginButton {
            id: lb
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: passwordInput.bottom
            anchors.topMargin: 20
            loginEnabled: loginInput.text.length > 0 && passwordInput.text.length > 0
            loginWorking: loginInProgress
            onTriggered: login()
          }
        }

        // "Email Login" page
        Column {
          id: emailLoginItem
          visible: mode === modes.email
          width: parent.width
          spacing: 20
          anchors.centerIn: parent

          Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: uiTr("Enter your email to log in")
            color: Theme.dashboard.textColor
            font.pixelSize: 16
            font.weight: Font.Medium
          }

          Text {
            id: emailErrorText
            color: {
              switch(emailError) {
              case errors.email_sent:
                return Theme.login.inputTextColor
              default:
                return Theme.login.errorTextColor
              }
            }
            text: {
              switch(emailError) {
              case errors.unknown:
                return uiTr("Something went wrong. Please try again later.")
              case errors.auth:
                return uiTr("Authentication error - check your email address")
              case errors.rate:
                return uiTr("Too many login attempts. Please try again later.")
              case errors.api:
                return uiTr("Network error - Can't reach the server")
              case errors.email_sent:
                return uiTr("Please check your email.")
              default:
                return ""
              }
            }
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: Theme.login.errorTextPx
            visible: emailError !== errors.none
          }

          LoginText {
            id: emailInput
            errorState: emailError !== errors.none && emailError !== errors.email_sent
            anchors.horizontalCenter: parent.horizontalCenter
            width: 260
            placeholderText: uiTr("Email Address")
            onAccepted: requestEmailLogin()
            validator: RegularExpressionValidator {
              regularExpression: /^\S+@\S+\.\S+$/
            }
          }

          LoginButton {
            id: sendEmailButton
            buttonText: uiTr("SEND EMAIL")
            anchors.horizontalCenter: parent.horizontalCenter
            loginEnabled: emailInput.text.length > 0 && emailInput.acceptableInput
            loginWorking: emailRequestInProgress
            onTriggered: requestEmailLogin()
          }
        }

        // Token input page
        Column {
          id: tokenLoginItem
          visible: mode === modes.token
          width: parent.width
          spacing: 20
          anchors.centerIn: parent

          Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: lastEmail ? uiTr("Enter the token sent to %1").arg(lastEmail) : uiTr("Enter the token from your email")
            color: Theme.dashboard.textColor
            width: parent.width * 0.8
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            font.pixelSize: 16
            font.weight: Font.Medium
          }

          Text {
            id: tokenErrorText
            color: Theme.login.errorTextColor
            text: {
              switch(tokenError) {
                case errors.unknown:
                  return uiTr("Something went wrong. Please try again.")
                case errors.auth:
                  return uiTr("Invalid token. Please check and try again.")
                case errors.rate:
                  return uiTr("Too many attempts. Please try again later.")
                case errors.api:
                  return uiTr("Network error - Can't reach the server")
                default:
                  return ""
              }
            }
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: Theme.login.errorTextPx
            visible: tokenError !== errors.none
          }

          LoginText {
            id: tokenInput
            errorState: tokenError !== errors.none
            anchors.horizontalCenter: parent.horizontalCenter
            width: 260
            placeholderText: uiTr("Token")
            onAccepted: validateToken()
          }

          LoginButton {
            id: validateTokenButton
            buttonText: uiTr("LOG IN")
            anchors.horizontalCenter: parent.horizontalCenter
            loginEnabled: tokenInput.text.length > 0
            loginWorking: tokenValidationInProgress
            onTriggered: validateToken()
          }
          
          TextLink {
            id: backToEmailLink
            text: uiTr("Back to email form")
            anchors.horizontalCenter: parent.horizontalCenter
            onClicked: {
              resetLoginPage(modes.email)
            }
          }
        }
      }

      Item {
        id: linkContainer
        anchors.top: loginContent.bottom
        anchors.topMargin: 20
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: 20
        anchors.rightMargin: 20
        height: buyAccount.height

        TextLink {
          id: loginMode
          visible: true
          text: {
            if(mode === modes.login)
              return uiTr("Log in with Email")
            else
              return uiTr("Log in with Username")
          }
          anchors.horizontalCenter: parent.horizontalCenter
          onClicked: {
            if(mode === modes.login)
              resetLoginPage(modes.email)
            else
              resetLoginPage(modes.login)
          }
        }

        TextLink {
          id: forgotPassword
          text: uiTr("Forgot Password")
          link: BrandHelper.getBrandParam("forgotPasswordLink")
          y: loginMode.y + loginMode.height + 8
          anchors.horizontalCenter: parent.horizontalCenter
          visible: mode === modes.login
        }

        TextLink {
          id: buyAccount
          text: uiTr("Buy Account")
          link: BrandHelper.getBrandParam("buyAccountLink")
          y: forgotPassword.visible ? (forgotPassword.y + forgotPassword.height + 8) : (loginMode.y + loginMode.height + 8)
          anchors.horizontalCenter: parent.horizontalCenter
        }
      }
    }

    // The "upgrade required" page - shown when the user's subscription has expired
    Item {
     id: upgradeRequired

      Image {
        id: upgradeRocket
        source: Theme.login.upgradeRocketImage
        height: 135
        width: (height / sourceSize.height) * sourceSize.width
        anchors.top: parent.top
        anchors.topMargin: 15
        anchors.horizontalCenter: parent.horizontalCenter
      }

     Text {
       id: upgradeText
       visible: true
       color: Theme.dashboard.textColor
       text: uiTr("Welcome Back!")
       font.pointSize: 15
       font.weight: Font.Bold
       anchors.top: upgradeRocket.bottom
       anchors.topMargin: 10
       anchors.horizontalCenter: parent.horizontalCenter
     }

     Text {
       id: upgradeMessageText
       visible: true
       color: Theme.dashboard.textColor
       width: upgradeRequired.width * 0.90
       text: uiTr("In order to use Private Internet Access, you'll need to renew your subscription.")
       wrapMode: Text.WordWrap
       horizontalAlignment: Text.AlignHCenter
       anchors.horizontalCenter: parent.horizontalCenter
       anchors.top: upgradeText.top
       anchors.topMargin: 50
     }

     LoginButton {
       id: upgradeButton
       buttonText: uiTr("RENEW NOW")
       anchors.horizontalCenter: parent.horizontalCenter
       anchors.top: upgradeMessageText.bottom
       anchors.topMargin: 35
       loginEnabled: true
       loginWorking: false
       onTriggered: {
         Qt.openUrlExternally(BrandHelper.getBrandParam("subscriptionLink"))
       }
     }

     TextLink {
       id: backToLoginLink
       text: uiTr("Back to login")
       anchors.top: upgradeButton.bottom
       anchors.topMargin: 20
       anchors.horizontalCenter: parent.horizontalCenter
       underlined: true
       onClicked: {
         stateStack.showLoginPage()
       }
     }
   }
  }

  function resetCreds() {
    loginInput.text = Daemon.account.username
    passwordInput.text = ""
    emailInput.text = ""
    tokenInput.text = ""
  }

  // If the daemon updates its credentials (mainly for a logout), reset the
  // credentials in the login page
  Connections {
    target: Daemon.account
    function onUsernameChanged() {
      resetCreds()
    }
  }

  Connections {
    target: NativeHelpers
    function onUrlOpenRequested(path, query) {
      if(path === "login" && query.token && query.token.length > 0 && !Daemon.account.loggedIn) {
        // Auto-fill the token input and switch to token mode
        tokenInput.text = query.token
        tokenError = errors.none
        mode = modes.token
        
        // Optionally, auto-validate the token immediately
        validateToken()
      }
    }
  }

  Connections {
    target: Daemon.account
    function onLoggedInChanged() {
      if(Daemon.account.loggedIn) {
        resetLoginPage();
      }
    }
  }

  function onEnter () {
    console.log('login onEnter')
    headerBar.logoCentered = false
    headerBar.needsBottomLine = false

    // Clear loginInProgress in case it was set by a prior login (it stays set
    // during the transition)
    loginInProgress = false
    shownError = errors.none
  }

  Component.onCompleted: {
    console.log('login onCompleted')
    // Load the initial stored credentials
    resetCreds()
  }
}