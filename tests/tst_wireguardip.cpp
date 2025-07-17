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

#include <common/src/common.h>
#include <common/src/openssl.h>
#include <common/src/crypto_helpers.h>
#include <common/src/builtin/path.h>
#include "src/testresource.h"
#include <QtTest>
#include <QDir>

namespace
{
    // Test case from real-world data - these are the test values provided
    // Private key (Base64 encoded) - from CLI tool
    const QString privateKeyB64 = QStringLiteral("6GTV3z3rzfrhGJra8ty4fFIM1BYlcpUBJKUdUOMbAHM=");
    
    // Server public key (Base64 encoded) - from server response
    const QString serverPubKeyB64 = QStringLiteral("pklf4CgVdFKVOr/Bvr038Vr6tS95vF2EAlN8BWBjulQ=");
    
    // Encrypted IP data (Base64 encoded) - from server response
    const QString encryptedIpB64 = QStringLiteral("HH9GWk2vGqacCS78SNaanH4oaHp6ozBTP5+NeoRWHgdS+/LmyVSFt24wM0ZCpAX9IL7+GTA3Fl3nlOUI3aG4RdjjL4WzIuvf6l0bQlv9ZrQTB9kBPSLa2nU=");
    
    // Expected decrypted IP address - from CLI verification tool
    const QString expectedIp = QStringLiteral("10.7.0.20");
}

// Test the WireGuard IP decryption functionality
class tst_wireguardip: public QObject
{
    Q_OBJECT

private slots:
    void initTestCase()
    {
        // We need to initialize the paths, so we can load OpenSSL libs
        Path::initializePreApp();
        Path::initializePostApp();
        
        // For tests, we might need to adjust the library paths
        qInfo() << "Current library path:" << Path::LibraryDir.str();
        
        // For testing, we'll try to load from the system library path if available
#ifdef Q_OS_MACOS
        // On macOS, we can find OpenSSL in /usr/local/lib or through Homebrew
        QStringList possibleLibPaths = {
            "/usr/local/lib",
            "/usr/local/opt/openssl/lib",
            "/opt/homebrew/lib"
        };
        
        for (const QString& path : possibleLibPaths) {
            QDir libDir(path);
            if (libDir.exists("libcrypto.3.dylib")) {
                qInfo() << "Found libcrypto.3.dylib in" << path;
                Path::LibraryDir = path;
                break;
            }
        }
#endif
    }

    // Test the WireGuard IP decryption using the real-world test case
    void testWireguardIPDecryption()
    {
        // Convert Base64 encoded keys to binary
        QByteArray privateKeyBytes = QByteArray::fromBase64(privateKeyB64.toLatin1());
        QByteArray serverPubKeyBytes = QByteArray::fromBase64(serverPubKeyB64.toLatin1());
        QByteArray encryptedData = QByteArray::fromBase64(encryptedIpB64.toLatin1());
        
        QCOMPARE(privateKeyBytes.size(), 32);
        QCOMPARE(serverPubKeyBytes.size(), 32);
        
        // Log test data for debugging
        qInfo() << "Test data:";
        qInfo() << "  Private key Base64: " << privateKeyB64;
        qInfo() << "  Server key Base64: " << serverPubKeyB64;
        qInfo() << "  Encrypted data Base64: " << encryptedIpB64;
        qInfo() << "  Expected IP: " << expectedIp;
        
        const unsigned char* privateKey = reinterpret_cast<const unsigned char*>(privateKeyBytes.constData());
        const unsigned char* serverPubKey = reinterpret_cast<const unsigned char*>(serverPubKeyBytes.constData());
        
        try {
            // Call the implementation - no special-case handling
            QString decryptedIp = decrypt_wireguard_ip(encryptedData, privateKey, serverPubKey);
            qInfo() << "Decrypted IP: " << decryptedIp;
            
            // Check if the decrypted IP begins with the expected prefix
            // Using startsWith instead of direct equality to handle trailing CIDR mask (/24) if present
            QVERIFY2(decryptedIp.startsWith(expectedIp), "Decrypted IP doesn't match expected value");
            
        } catch (const std::exception& e) {
            // If decryption fails, fail the test
            QFAIL(QStringLiteral("Exception during decryption: %1").arg(e.what()).toUtf8().constData());
        }
    }
};

QTEST_GUILESS_MAIN(tst_wireguardip)
#include "tst_wireguardip.moc"