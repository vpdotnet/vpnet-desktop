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

#include "apibase.h"
#include <QMutex>
#include <QMap>

// Static registry for server certificates
namespace {
    QMutex certificateMutex;
    QMap<QString, QSslCertificate> serverCertificates;
}

void ApiBase::registerServerCertificate(const QString &serverIp, const QSslCertificate &cert)
{
    if (serverIp.isEmpty() || cert.isNull()) {
        qWarning() << "Cannot register null or empty certificate for server:" << serverIp;
        return;
    }
    
    QMutexLocker locker(&certificateMutex);
    serverCertificates[serverIp] = cert;
    qInfo() << "Registered certificate for server IP:" << serverIp 
            << "with CN:" << cert.subjectInfo(QSslCertificate::CommonName).join(", ")
            << "expiring:" << cert.expiryDate();
}

std::optional<QSslCertificate> ApiBase::getLatestCertificate(const QString &serverIp)
{
    QMutexLocker locker(&certificateMutex);
    
    // For WireGuard servers, extract the actual IP address from the URI
    // This handles URIs like https://178.162.222.218:1337/ where 178.162.222.218 is the IP
    QString effectiveIp = serverIp;
    
    // Debug the input
    qDebug() << "Looking for certificate for:" << serverIp;
    
    // If we have a full URI, extract just the IP address part
    if (serverIp.startsWith("http")) {
        QUrl url(serverIp);
        effectiveIp = url.host();
        qDebug() << "Extracted from URL:" << effectiveIp;
    }
    
    // Remove port if present in the host
    int colonPos = effectiveIp.lastIndexOf(':');
    if (colonPos > 0) {
        effectiveIp = effectiveIp.left(colonPos);
        qDebug() << "Removed port, effective IP:" << effectiveIp;
    }
    
    // Try finding the certificate with the exact IP
    auto it = serverCertificates.find(effectiveIp);
    if (it != serverCertificates.end()) {
        qDebug() << "Found certificate for IP:" << effectiveIp;
        return it.value();
    }
    
    // If not found, print all registered certificates for debugging
    if (serverCertificates.isEmpty()) {
        qWarning() << "No certificates registered in the registry";
    } else {
        qDebug() << "Certificate not found. Registered certificates:";
        for (auto regIt = serverCertificates.begin(); regIt != serverCertificates.end(); ++regIt) {
            qDebug() << "  - IP:" << regIt.key() 
                    << "CN:" << regIt.value().subjectInfo(QSslCertificate::CommonName).join(", ");
        }
    }
    
    return std::nullopt;
}

bool ApiBase::updatePrivateCAWithLatestCertificate(const QString &serverIp, std::shared_ptr<PrivateCA> &pCA)
{
    if (!pCA) {
        qWarning() << "Cannot update null PrivateCA for server:" << serverIp;
        return false;
    }
    
    auto latestCert = getLatestCertificate(serverIp);
    if (!latestCert) {
        return false;
    }
    
    // If the current certificate is different from stored one, update it
    if (pCA->storedCertificate().isNull() || pCA->storedCertificate() != *latestCert) {
        pCA->setStoredCertificate(*latestCert);
        qInfo() << "Updated certificate for server:" << serverIp;
        return true;
    }
    
    return false;
}

ApiBaseData::ApiBaseData(const std::vector<QString> &baseUris)
    : _baseUris{}, _nextStartIndex{0}
{
    _baseUris.reserve(baseUris.size());
    for(auto &uri : baseUris)
        addBaseUri(uri, {}, {});
}

ApiBaseData::ApiBaseData(const std::initializer_list<QString> &baseUris)
    : _baseUris{}, _nextStartIndex{0}
{
    _baseUris.reserve(baseUris.size());
    for(auto &uri : baseUris)
        addBaseUri(uri, {}, {});
}

ApiBaseData::ApiBaseData(const QString &uri, std::shared_ptr<PrivateCA> pCA,
                         const QString &peerVerifyName)
    : _baseUris{}, _nextStartIndex{0}
{
    addBaseUri(uri, std::move(pCA), peerVerifyName);
}

ApiBaseData::ApiBaseData(const QString &uri, std::shared_ptr<PrivateCA> pCA,
                         const QString &peerVerifyName, TlsValidationCallback tlsCallback)
    : _baseUris{}, _nextStartIndex{0}
{
    addBaseUri(uri, std::move(pCA), peerVerifyName, std::move(tlsCallback));
}


ApiBaseData::ApiBaseData(std::vector<BaseUri> baseUris)
    : _baseUris{std::move(baseUris)}, _nextStartIndex{0}
{
    // Ensure all bases end with '/'
    for(auto &base : _baseUris)
    {
        if(!base.uri.endsWith('/'))
            base.uri += '/';
    }
}

void ApiBaseData::addBaseUri(const QString &uri, std::shared_ptr<PrivateCA> pCA,
                             const QString &peerVerifyName,
                             TlsValidationCallback tlsCallback)
{
    if(!uri.endsWith('/'))
        _baseUris.push_back({uri + '/', std::move(pCA), peerVerifyName, std::move(tlsCallback)});
    else
        _baseUris.push_back({uri, std::move(pCA), peerVerifyName, std::move(tlsCallback)});
}

BaseUri ApiBaseData::getUri(unsigned index)
{
    Q_ASSERT(index < _baseUris.size());   // Guaranteed by caller
    return _baseUris[index];
}

void ApiBaseData::attemptSucceeded(unsigned successIndex)
{
    Q_ASSERT(successIndex < _baseUris.size());  // Guaranteed by caller
    _nextStartIndex = successIndex;
}

ApiBaseSequence FixedApiBase::beginAttempt()
{
    Q_ASSERT(_pData);   // Class invariant
    return {_pData};
}

unsigned FixedApiBase::getAttemptCount(unsigned attemptsPerBase)
{
    Q_ASSERT(_pData);   // Class invariant
    return _pData->getUriCount() * attemptsPerBase;
}


ApiBaseSequence::ApiBaseSequence(QSharedPointer<ApiBaseData> pData)
    : _pData{std::move(pData)}
{
    Q_ASSERT(_pData);   // Guaranteed by caller

    // Back up _nextBaseUri relative to the start so getNextUri() can increment
    // it normally
    unsigned startIndex = _pData->getNextStartIndex();
    _currentBaseUri = startIndex ? startIndex-1 : _pData->getUriCount()-1;
}

BaseUri ApiBaseSequence::getNextUri()
{
    Q_ASSERT(_pData);   // Class invariant
    _currentBaseUri = (_currentBaseUri + 1) % _pData->getUriCount();
    return _pData->getUri(_currentBaseUri);
}

void ApiBaseSequence::attemptSucceeded()
{
    Q_ASSERT(_pData);   // Class invariant
    _pData->attemptSucceeded(_currentBaseUri);
}
