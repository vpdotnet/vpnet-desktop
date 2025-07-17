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
#line SOURCE_FILE("environment.cpp")

#include "environment.h"
#include <common/src/builtin/path.h>
#include "metaserviceapibase.h"
#include "brand.h"
#include <QFile>
#include <QSslCertificate>
#include <QSslKey>
#include <QJsonDocument>
#include <QJsonArray>

// Hash: f37e8dca5b60bb235284be2d4e54cb29813cb566569886c48c55336096362873
const QByteArray Environment::defaultRegionsListPublicKey = QByteArrayLiteral(
    "-----BEGIN PUBLIC KEY-----\n"
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxSqleT52eqaEfBcgInai\n"
    "J1y6p82WsnATs2pEMkw2m0COOP6/2DFrAZMtEHbbxdHsS2Rax6yqw7awFY+VAI9X\n"
    "k6m52Rhr6l1mVFRXCu9vPU2T3qmgQyMFQ2TdK1ybMTDrKE/v3d53VCLIZEtQLi0u\n"
    "/IiFFN7QqyQ7CJB3Pod6kHdbLa9Tw6LIWw5W0Lg1R7VKi7t+kEWirHDnhiJ8y3vO\n"
    "cXdts1NiBsqlt66A/Y/pBkM1MCE8eQKkKDGxBeXCarkvtAvaTXl6o1hmivQh9UXo\n"
    "L+aT0S9gNbB645fiEIfHGHrfMeUVeyUJTBt/BVErpETj0WbolM1whzw6CTT8q5zU\n"
    "IefYNjpLdPo6ggl8OCcdy/2YBh/2vSQNOpeOJh6nw+K8t3CkkWbhbZv/KHkFP+mX\n"
    "X9zhwqvNP9ZbwEunOlk3f4IgdCuydmgRkwHvwK4eEJW2dRvoC0RMd9LOJ2KHC4OT\n"
    "gKyjNmubfEaFehGP04Oh9SJyvJPWNtzFg9pEQGnBtQOs3M/La4ePbRxHvoc14Mke\n"
    "DvJb51JF7zSPw8aC4FpzmPfLCjlVNQh5QUe8NALVr4nHC5kgqD04Gm9mOW3moOUJ\n"
    "Zd4P4lKaVpGDDGCcDQzLVtK6WK/jtAOsugf1RsBOrIidb6UVa16q32oiHmN1tXqS\n"
    "G0/YY/gsigdiXvtD5nRn7uECAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n"
);

Environment::Environment(const StateModel &state)
    : _state{state}
{
    reload();
}

QByteArray Environment::readFile(const QString &path)
{
    QFile file{path};
    if(!file.open(QIODevice::OpenModeFlag::ReadOnly | QIODevice::OpenModeFlag::Text))
        return {};
    return file.readAll();
}

void Environment::loadCertificateAuthority(const QString &handshakeSetting,
                                           const QString &filename)
{
    const QString &resourceName = handshakeSetting + QStringLiteral(" CA");

    auto overrideFilePath = Path::DaemonSettingsDir / QStringLiteral("ca_override") / filename;
    if(QFile::exists(overrideFilePath))
    {
        QByteArray fileData = readFile(overrideFilePath);
        // Strip CR - normalize line endings to LF.
        fileData.replace('\r', QByteArray{});
        // Make sure the file is a valid cert, even though we store the raw PEM
        QSslCertificate testCert{fileData};
        if(testCert.isNull())
        {
            qWarning() << "Override certificate" << overrideFilePath
                << "can't be parsed";
            emit overrideFailed(resourceName);
            // Proceed to load default certificate
        }
        else
        {
            qInfo() << "Overriding" << handshakeSetting << "CA with:"
                << overrideFilePath;
            emit overrideActive(resourceName);
            _authorities.emplace(handshakeSetting, std::move(fileData));
            return;
        }
    }

    // No override, or it couldn't be parsed, load the default.
    QByteArray defaultData = readFile(QStringLiteral(":/ca/") + filename);
    defaultData.replace('\r', QByteArray{});
    _authorities.emplace(handshakeSetting, std::move(defaultData));
}

void Environment::loadRegionsListPublicKey()
{
    auto overrideFilePath = Path::DaemonSettingsDir / QStringLiteral("regions_key_override.pem");

    if(QFile::exists(overrideFilePath))
    {
        QByteArray fileData = readFile(overrideFilePath);
        // Make sure it's a valid public key, even though we store the raw PEM
        QSslKey testKey{fileData, QSsl::KeyAlgorithm::Rsa,
                        QSsl::EncodingFormat::Pem, QSsl::KeyType::PublicKey};
        if(testKey.isNull())
        {
            qWarning() << "Override regions list key" << overrideFilePath
                << "can't be parsed";
            emit overrideFailed(QStringLiteral("regions list key"));
            // Proceed to load default
        }
        else
        {
            qInfo() << "Overriding regions list key with:" << overrideFilePath;
            emit overrideActive(QStringLiteral("regions list key"));
            _regionsListPublicKey = fileData;
            return;
        }
    }

    // Load default
    _regionsListPublicKey = defaultRegionsListPublicKey;
}

void Environment::applyApiBaseOverride(bool overridePresent,
                                       const QJsonDocument &apiOverride,
                                       std::shared_ptr<ApiBase> &pApiBase,
                                       const QString &jsonKey,
                                       const QString &resourceName)
{
    // Check failure conditions first to trace specific failures

    // File present but couldn't be loaded - emit overrideFailed()
    if(overridePresent && apiOverride.isNull())
    {
        // Don't need to trace, failure to load the JSON was traced separately
        emit overrideFailed(resourceName);
        return;
    }

    auto overrideBasesValue = apiOverride[jsonKey];
    // Unexpected value type.  null, undefined, or an empty array are normal,
    // these indicate not to override this particular API base.
    if(!overrideBasesValue.isNull() && !overrideBasesValue.isUndefined() &&
       !overrideBasesValue.isArray())
    {
        qWarning() << "Can't override" << resourceName << "- incorrect value for"
            << jsonKey << "- expected array, got"
            << overrideBasesValue;
        emit overrideFailed(resourceName);
        return;
    }

    // If it's null, undefined, or empty, that's normal, don't override.
    // (null or undefined produce an empty array when calling
    // QJsonValue::toArray()).
    auto overrideBases = overrideBasesValue.toArray();
    if(overrideBases.isEmpty())
    {
        // No trace - this is the normal case
        return;
    }

    // Ensure all values are strings
    std::vector<QString> overrideBaseStrs;
    overrideBaseStrs.reserve(overrideBases.size());
    int pos = 0;   // Just for tracing
    for(const auto &value : overrideBases)
    {
        // Non-string or empty values aren't allowed
        overrideBaseStrs.push_back(value.toString());
        if(overrideBaseStrs.back().isEmpty())
        {
            qWarning() << "Can't override" << resourceName
                << "- incorrect value at position" << pos << "-" << value;
            emit overrideFailed(resourceName);
            return;
        }
        ++pos;
    }

    qInfo() << "Overriding" << resourceName << "with" << overrideBaseStrs;
    pApiBase = std::make_shared<FixedApiBase>(overrideBaseStrs);
    emit overrideActive(resourceName);
}

void Environment::loadApiBase(bool overridePresent,
                              const QJsonDocument &apiOverride,
                              std::shared_ptr<ApiBase> &pApiBase,
                              const QString &jsonKey,
                              const QString &resourceName,
                              const std::initializer_list<QString> &defaults)
{
    pApiBase.reset();
    // Apply the override if it's set and valid
    applyApiBaseOverride(overridePresent, apiOverride, pApiBase, jsonKey,
                         resourceName);
    // If the override wasn't applied, load the default.  applyApiBaseOverride()
    // traces and emits overrideFailed() as appropriate.
    if(!pApiBase)
        pApiBase = std::make_shared<FixedApiBase>(defaults);
}

void Environment::loadDynamicApiBase(bool overridePresent,
                                     const QJsonDocument &apiOverride,
                                     std::shared_ptr<ApiBase> &pApiBase,
                                     const QString &jsonKey,
                                     const QString &resourceName,
                                     const QString &dynamicBasePath,
                                     const std::initializer_list<QString> &fixedBases)
{
    pApiBase.reset();
    applyApiBaseOverride(overridePresent, apiOverride, pApiBase, jsonKey,
                         resourceName);
    // If it wasn't overridden, use the dynamic API base, which leverages Meta
    // services and the fixed fallbacks
    if(!pApiBase)
    {
        pApiBase = std::make_shared<MetaServiceApiBase>(_state, dynamicBasePath,
                                                        _pRsa4096CA, fixedBases);
    }
}

void Environment::loadApiBases()
{
    QByteArray apiOverrideJson = readFile(Path::DaemonSettingsDir / QStringLiteral("api_override.json"));
    // Flag to indicate whether the override file was present at all - if it was
    // present and couldn't be loaded, this causes each API base to emit
    // overrideFailed().
    bool overridePresent = !apiOverrideJson.isEmpty();
    // Only try to parse if the file was present and non-empty - don't trace
    // bogus errors if the file was not present
    QJsonDocument apiOverride;
    if(overridePresent)
    {
        QJsonParseError parseError;
        apiOverride = QJsonDocument::fromJson(apiOverrideJson, &parseError);
        if(apiOverride.isNull())
        {
            qWarning() << "Can't parse api_override.json:" << parseError.errorString();
        }
    }

    // Load each API base
    loadApiBase(overridePresent, apiOverride, _pApiv1, QStringLiteral("apiv1"),
                QStringLiteral("API v1"), {
                    QStringLiteral("https://vp.net/_rest/Network/VPN:apiV1?resource="),
                });
    loadDynamicApiBase(overridePresent, apiOverride, _pApiv2, QStringLiteral("apiv2"),
                QStringLiteral("API v2"), QStringLiteral("/apiv2/"), {
                    QStringLiteral("https://vp.net/_rest/Network/VPN:apiV2?resource="),
                });

    loadDynamicApiBase(overridePresent, apiOverride, _pModernRegionsListApi,
                QStringLiteral("modern_regions_list_api"),
                QStringLiteral("modern regions list API"), QStringLiteral("/"), {
                    QStringLiteral("https://serverlist.vp.net")
                });

    loadApiBase(overridePresent, apiOverride, _pIpAddrApi, QStringLiteral("ip_api"),
                QStringLiteral("IP API"), {
                    QStringLiteral("https://vp.net/_rest/Network/VPN:ip?resource=")
                });
    loadApiBase(overridePresent, apiOverride, _pIpProxyApi, QStringLiteral("ip_proxy_api"),
                QStringLiteral("IP proxy API"), {
                    QStringLiteral("https://api.piaproxy.net/")
                });
    loadApiBase(overridePresent, apiOverride, _pUpdateApi, QStringLiteral("update_api"),
                QStringLiteral("update API"), {
                    BRAND_UPDATE_APIS
                });
}

void Environment::reload()
{
    _authorities.clear();
    // Note: Removed dependency on rsa_4096.crt
    _pRsa4096CA = nullptr; // No longer using a custom CA for API requests

    loadRegionsListPublicKey();

    loadApiBases();
}

QByteArray Environment::getCertificateAuthority(const QString &type) const
{
    auto itAuthority = _authorities.find(type);
    if(itAuthority != _authorities.end())
        return itAuthority->second;
    qWarning() << "Unable to find certificate authority" << type;
    auto itDefault = _authorities.find(QStringLiteral("default"));
    Q_ASSERT(itDefault != _authorities.end());
    return itDefault->second;
}
