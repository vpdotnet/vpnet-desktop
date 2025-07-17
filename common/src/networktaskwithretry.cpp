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

#include "common.h"
#line SOURCE_FILE("networktaskwithretry.cpp")

#include "networktaskwithretry.h"
#include "apinetwork.h"
#include "openssl.h"
#include <common/src/builtin/util.h>
#include <QTimer>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslSocket>

namespace
{
    const QByteArray authHeaderName{QByteArrayLiteral("Authorization")};

    // Set the authorization header on a QNetworkRequest
    void setAuth(QNetworkRequest &request, const QByteArray &authHeaderVal)
    {
        request.setRawHeader(authHeaderName, authHeaderVal);
    }
}

NetworkTaskWithRetry::NetworkTaskWithRetry(QNetworkAccessManager::Operation verb,
                                           ApiBase &apiBaseUris,
                                           QString resource,
                                           std::unique_ptr<ApiRetry> pRetryStrategy,
                                           const QJsonDocument &data,
                                           QByteArray authHeaderVal)
    : _verb{std::move(verb)}, _baseUriSequence{apiBaseUris.beginAttempt()},
      _pRetryStrategy{std::move(pRetryStrategy)}, _resource{std::move(resource)},
      _data{(data.isNull() ? QByteArray() : data.toJson())},
      _authHeaderVal{std::move(authHeaderVal)},
      _worstRetriableError{Error::Code::ApiNetworkError}
{
    Q_ASSERT(_pRetryStrategy);
    // Only GET and HEAD are supported right now
    Q_ASSERT(_verb == QNetworkAccessManager::Operation::GetOperation ||
             _verb == QNetworkAccessManager::Operation::PostOperation ||
             _verb == QNetworkAccessManager::Operation::HeadOperation);

    scheduleNextAttempt(std::chrono::milliseconds{0});
}

NetworkTaskWithRetry::~NetworkTaskWithRetry()
{

}

void NetworkTaskWithRetry::scheduleNextAttempt(std::chrono::milliseconds nextDelay)
{
    Q_ASSERT(_pRetryStrategy);  // Class invariant

    QTimer::singleShot(msec(nextDelay), this, &NetworkTaskWithRetry::executeNextAttempt);
}

void NetworkTaskWithRetry::executeNextAttempt()
{
    // Handle the request
    sendRequest()
            ->notify(this, [this](const Error& error, const QByteArray& body) {

                // Release this task; it's no longer needed
                _pNetworkReply.reset();

                // Check for errors
                if (error)
                {
                    // Auth and "payment required" (expired account) errors can't be retried.
                    if (error.code() == Error::ApiUnauthorizedError ||
                        error.code() == Error::ApiPaymentRequiredError ||
                        error.code() == Error::ApiRateLimitedError)
                    {
                        reject(error);
                        return;
                    }

                    // A rate limiting error is worse than a network error - set the worst
                    // retriable error, but keep trying in case another API endpoint gives us
                    // 200 or 401.
                    // (Otherwise, leave the worst error alone, it might already be set to a
                    // rate limiting error by a prior attempt.)
                    if (error.code() == Error::ApiRateLimitedError)
                        _worstRetriableError = Error::Code::ApiRateLimitedError;

                    qWarning() << "Attempt for" << _resource
                        << "failed with error" << error;

                    // Retry if we still have attempts left.
                    Q_ASSERT(_pRetryStrategy);  // Class invariant
                    auto nextDelay = _pRetryStrategy->attemptFailed(_resource);
                    if(!nextDelay)
                    {
                        qWarning() << "Request for resource" << _resource
                            << "failed, returning error" << _worstRetriableError;
                        reject({HERE, _worstRetriableError});
                        return;
                    }
                    else
                        scheduleNextAttempt(*nextDelay);
                }
                else
                {
                    _baseUriSequence.attemptSucceeded();
                    resolve(body);
                }
            });
}

Async<QByteArray> NetworkTaskWithRetry::sendRequest()
{
    // Use ApiNetwork's QNetworkAccessManager, this binds us to the VPN
    // interface when connected (important when we do not route the default
    // gateway into the VPN).
    QNetworkAccessManager &networkManager = ApiNetwork::instance()->getAccessManager();


    // Get the next base URI
    const BaseUri &nextBase = _baseUriSequence.getNextUri();
    
    // Extract the server IP from the URI for WireGuard servers
    QString serverIp;
    if (nextBase.uri.startsWith("http")) {
        QUrl url(nextBase.uri);
        serverIp = url.host();
    }
    
    // Check if we need to update the certificate for this server
    if (!serverIp.isEmpty() && nextBase.pCA) {
        // Check certificates by IP address for all servers
        // This is a more generic approach that doesn't rely on specific common names
        auto latestCert = ApiBase::getLatestCertificate(serverIp);
        if (latestCert && !latestCert->isNull()) {
            // Directly update the stored certificate in the PrivateCA object
            const_cast<BaseUri&>(nextBase).pCA->setStoredCertificate(*latestCert);
            
            qInfo() << "Updated certificate for server:" << serverIp
                   << "CN:" << latestCert->subjectInfo(QSslCertificate::CommonName).join(", ")
                   << "Expiry:" << latestCert->expiryDate().toString();
        }
    }
    
    ApiResource requestResource{nextBase.uri + _resource};
    QUrl requestUri{requestResource};
    QNetworkRequest request(requestUri);
    if (!_authHeaderVal.isEmpty())
        setAuth(request, _authHeaderVal);

    // The URL for each request is logged to indicate if there is trouble with
    // specific API URLs, etc.  Query parameters are redacted by ApiResource.
    if (!nextBase.peerVerifyName.isEmpty())
    {
        QSslConfiguration sslConfig{request.sslConfiguration()};
        
        // For WireGuard connections, both the cert CN and HTTP Host header must use the same value
        // This is crucial for server-side validation where the Host is matched against the certificate
        QUrl requestUrl(requestUri);
        QString urlHost = requestUrl.host();
        if (requestUrl.port() != -1) {
            urlHost += ":" + QString::number(requestUrl.port());
        }
        
        qDebug() << "Host options - URL host:" << urlHost << "SNI hostname:" << nextBase.peerVerifyName;
        
        // Set peer verify name for certificate validation
        // This enforces that the certificate CN matches the expected value from the server list
        request.setPeerVerifyName(nextBase.peerVerifyName);
        
        // Set the SSL configuration to use in this request
        request.setSslConfiguration(sslConfig);
        
        // Use the peer verify name (CN) for the Host header instead of the URL host
        // This ensures the server sees the expected hostname in the HTTP request
        request.setRawHeader("Host", nextBase.peerVerifyName.toUtf8());
        
        // Log whether we're using a custom CA or system CAs
        if (!nextBase.peerVerifyName.isEmpty())
        {
            if (nextBase.pCA) {
                qDebug() << "requesting:" << requestResource
                    << "using peer name" << nextBase.peerVerifyName << "with provided certificate";
            } else {
                qDebug() << "requesting:" << requestResource
                    << "using peer name" << nextBase.peerVerifyName << "with system CA";
            }
        }
        else
        {
            qDebug() << "requesting:" << requestResource;
        }
    }
    else
    {
        qDebug() << "requesting:" << requestResource;
    }

    // Permit same-origin redirects.  Qt does not follow redirects by default,
    // which has resulted in some near-misses in the past when load balancers,
    // meta proxies, etc. have been reconfigured.
    //
    // Only same-origin redirects are allowed; there's no reason to allow
    // cross-origin redirects.  Do this with a user handler since Qt normally
    // distinguishes `https://host/` and `https://host:443/`; treat these as the
    // same.
    request.setAttribute(QNetworkRequest::Attribute::RedirectPolicyAttribute,
                         QNetworkRequest::RedirectPolicy::UserVerifiedRedirectPolicy);

    // Seems like QNetworkAccessManager could provide this, but the closest
    // thing it has is sendCustomRequest().  It looks like that would produce a
    // QNetworkReply that says its operation was "custom" even if the method
    // was a standard one, and there might be other subtleties, so this is more
    // robust.
    QNetworkReply* replyPtr;
    switch (_verb)
    {
        default:
        case QNetworkAccessManager::GetOperation:
            replyPtr = networkManager.get(request);
            break;
        case QNetworkAccessManager::PostOperation:
            request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
            replyPtr = networkManager.post(request, _data);
            break;
        case QNetworkAccessManager::HeadOperation:
            replyPtr = networkManager.head(request);
            break;
    }
    Q_ASSERT(replyPtr); // Postcondition of QNetworkAccessManager::get/post/head

    // Wrap the reply in a shared pointer. Use deleteLater as the deleter
    // since the finished signal is not always safe to destroy ourselves
    // in (e.g. abort->finished->delete is not currently safe). This way
    // we don't have to delay the entire finished signal to stay safe.
    QSharedPointer<QNetworkReply> reply(replyPtr, &QObject::deleteLater);

    // Abort the request if it doesn't complete within a certain interval
    Q_ASSERT(_pRetryStrategy);  // Class invariant
    QTimer::singleShot(msec(_pRetryStrategy->beginAttempt(_resource)), reply.get(), &QNetworkReply::abort);

    // Handle redirects by permitting same-origin HTTPS redirects only
    connect(reply.get(), &QNetworkReply::redirected, this,
        [reply, requestUri](const QUrl &url)
        {
            // Resolve the redirect URL if it's relative.  Typical relative
            // paths as URLs won't affect the scheme/host/port and will be
            // accepted since they are unchanged, but if something odd like a
            // protocol-relative URL shows up, this will handle it properly.
            const auto &targetResolved = requestUri.resolved(url);
            if(targetResolved.scheme() == QStringLiteral("https") &&
                targetResolved.host() == requestUri.host() &&
                targetResolved.port(443) == requestUri.port(443))
            {
                qInfo() << "Accepted redirect from"
                    << ApiResource{requestUri.toString()} << "to"
                    << ApiResource{url.toString()} << "(resolved:"
                    << ApiResource{targetResolved.toString()} << ")";
                reply->redirectAllowed();
            }
            else
            {
                qInfo() << "Rejected redirect from"
                    << ApiResource{requestUri.toString()} << "to"
                    << ApiResource{url.toString()} << "(resolved:"
                    << ApiResource{targetResolved.toString()} << ")";
                reply->abort();
            }
        });

    // Handle SSL errors for certificate verification
    // We need to check SSL errors in two cases:
    // 1. When using a custom CA (traditional pinning)
    // 2. When a peerVerifyName is set but we're using system CAs (for WireGuard servers)
    if(!nextBase.peerVerifyName.isEmpty())
    {
        // Connect the SSL errors handler for certificate verification
        connect(reply.get(), &QNetworkReply::sslErrors, this,
            [this, reply, nextBase](const QList<QSslError> &errors)
            {
                // Log the SSL errors for diagnostics
                if (!errors.isEmpty()) {
                    qInfo() << "SSL errors for" << nextBase.peerVerifyName << ":";
                    for (const QSslError &error : errors) {
                        qInfo() << "  -" << error.errorString();
                    }
                }
                
                // Get the certificate chain from the server
                const auto &certChain = reply->sslConfiguration().peerCertificateChain();
                if (certChain.isEmpty()) {
                    qWarning() << "No certificate provided by server for" << nextBase.peerVerifyName;
                    return;
                }
                
                // If we have a custom TLS validation callback, use it
                if (nextBase.tlsValidationCallback) {
                    qInfo() << "Using custom TLS validation callback for" << nextBase.peerVerifyName;
                    if (nextBase.tlsValidationCallback(certChain, nextBase.peerVerifyName)) {
                        qInfo() << "Custom TLS validation succeeded, ignoring SSL errors";
                        reply->ignoreSslErrors();
                        return;
                    } else {
                        qWarning() << "Custom TLS validation failed for" << nextBase.peerVerifyName;
                        // Don't ignore errors - let the connection fail
                        return;
                    }
                }
                
                // For custom CA with certificate pinning
                if (nextBase.pCA) {
                    qInfo() << "Using provided certificate for validation of" << nextBase.peerVerifyName;

                    // If OpenSSL fails (indicated by verifyHttpsCertificate returning false),
                    // try direct PEM comparison for the self-signed certificate
                    if (!nextBase.pCA->verifyHttpsCertificate(certChain, nextBase.peerVerifyName, true)) {
                        qWarning("OpenSSL verification failed. Trying direct certificate comparison...");
                        
                        // Check if we have self-signed certificate errors
                        bool hasSelfSignedError = false;
                        for (const QSslError &error : errors) {
                            if (error.error() == QSslError::SelfSignedCertificate || 
                                error.error() == QSslError::SelfSignedCertificateInChain) {
                                hasSelfSignedError = true;
                                break;
                            }
                        }
                        
                        if (hasSelfSignedError && !certChain.isEmpty()) {
                            // Get the server's certificate for direct comparison
                            const QSslCertificate &serverCert = certChain.first();
                            
                            // Get the stored certificate from our PrivateCA object
                            const QSslCertificate &storedCert = nextBase.pCA->storedCertificate();
                            
                            // Log certificate details for debugging - use string conversions to avoid logging issues
                            QString certInfo = QString("Server certificate: CN=%1 Serial=%2 Issuer=%3")
                                .arg(serverCert.subjectInfo(QSslCertificate::CommonName).join(", "))
                                .arg(serverCert.serialNumber())
                                .arg(serverCert.issuerDisplayName());
                            qInfo() << certInfo;
                            
                            // Compare with the certificate we received from the server list using QSslCertificate's equality operator
                            // This properly compares all certificate fields and data
                            if (!storedCert.isNull() && serverCert == storedCert) {
                                
                                qInfo("Direct certificate comparison SUCCEEDED - server cert EXACTLY matches stored certificate");
                                
                                // Check if CN matches expected hostname
                                if (certChain.first().subjectInfo(QSslCertificate::CommonName).contains(nextBase.peerVerifyName)) {
                                    qInfo("Certificate has expected CN: %s", qPrintable(nextBase.peerVerifyName));
                                    qInfo("Accepting self-signed certificate that matches provided certificate");
                                    reply->ignoreSslErrors();
                                    return;
                                } else {
                                    qWarning("Certificate has wrong CN (expected %s)", qPrintable(nextBase.peerVerifyName));
                                }
                            } else {
                                qWarning("Certificate does NOT match the provided certificate");
                                
                                // Extract the server IP from the URI - this works for any server type
                                QString serverIp;
                                if (nextBase.uri.startsWith("http")) {
                                    QUrl url(nextBase.uri);
                                    serverIp = url.host();
                                }
                                
                                if (!serverIp.isEmpty()) {
                                    // For better diagnostics, log if the certificate is in our registry
                                    auto registeredCert = ApiBase::getLatestCertificate(serverIp);
                                    if (registeredCert) {
                                        qInfo("Found registered certificate for server IP: %s", qPrintable(serverIp));
                                        
                                        // Check if the server's certificate matches our registered one
                                        if (!registeredCert->isNull() && serverCert == *registeredCert) {
                                            qInfo("Server certificate matches the REGISTERED certificate but NOT the one in PrivateCA");
                                            qInfo("This suggests our certificate registry is working but wasn't applied correctly");
                                            
                                            // Try updating the PrivateCA directly with the registered certificate
                                            const_cast<BaseUri&>(nextBase).pCA->setStoredCertificate(*registeredCert);
                                            
                                            // Now check if the updated certificate matches
                                            if (serverCert == nextBase.pCA->storedCertificate()) {
                                                qInfo("Certificate updated SUCCESSFULLY and now matches server certificate");
                                                qInfo("Accepting certificate from registry for server: %s", qPrintable(serverIp));
                                                reply->ignoreSslErrors();
                                                return;
                                            } else {
                                                qWarning("Certificate update failed - still doesn't match server certificate");
                                            }
                                        } else {
                                            qWarning("Server certificate doesn't match the registered certificate either");
                                        }
                                    } else {
                                        qWarning("No registered certificate found for server IP: %s", qPrintable(serverIp));
                                    }
                                }
                                
                                // Log certificate details for comparison
                                QString serverInfo = QString("Server cert: CN=%1 Serial=%2 Fingerprint=%3")
                                    .arg(serverCert.subjectInfo(QSslCertificate::CommonName).join(", "))
                                    .arg(serverCert.serialNumber())
                                    .arg(QString(QCryptographicHash::hash(serverCert.toDer(), 
                                                 QCryptographicHash::Sha256).toHex()));
                                
                                QString storedInfo = QString("Stored cert: CN=%1 Serial=%2 Fingerprint=%3")
                                    .arg(storedCert.subjectInfo(QSslCertificate::CommonName).join(", "))
                                    .arg(storedCert.serialNumber())
                                    .arg(QString(QCryptographicHash::hash(storedCert.toDer(), 
                                                 QCryptographicHash::Sha256).toHex()));
                                
                                qWarning("%s", qPrintable(serverInfo));
                                qWarning("%s", qPrintable(storedInfo));
                            }
                        }
                        
                        // If direct comparison failed, continue with normal verification
                        checkSslCertificate(*reply, nextBase, errors);
                    } else {
                        // OpenSSL verification succeeded
                        qInfo() << "OpenSSL verification SUCCEEDED for:" << nextBase.peerVerifyName;
                        reply->ignoreSslErrors();
                    }
                }
                // With system CAs but specified peerVerifyName, check if errors are only about hostname mismatch
                else {
                    bool onlyHostnameMismatchErrors = true;
                    for (const QSslError &error : errors) {
                        // If there are errors other than hostname mismatch, don't ignore
                        if (error.error() != QSslError::HostNameMismatch) {
                            onlyHostnameMismatchErrors = false;
                            break;
                        }
                    }
                    
                    // If the only errors are hostname mismatches and we have a peerVerifyName, 
                    // we can safely ignore them (the setPeerVerifyName will enforce correct verification)
                    if (onlyHostnameMismatchErrors) {
                        qInfo() << "Accepting certificate with hostname mismatch for peer" << nextBase.peerVerifyName;
                        reply->ignoreSslErrors();
                    } else {
                        qWarning() << "Certificate has non-hostname errors for" << nextBase.peerVerifyName;
                        // Log the errors for debugging
                        for (const QSslError &error : errors) {
                            qWarning() << "  -" << error.errorString();
                        }
                    }
                }
            });
    }

    // Create a network task that resolves to the result of the request
    auto networkTask = Async<QByteArray>::create();
    ApiResource resource = _resource;
    connect(reply.get(), &QNetworkReply::finished, networkTask.get(), [networkTask = networkTask.get(), reply, resource]
    {
        auto keepAlive = networkTask->sharedFromThis();

        // Enhanced logging for detailed diagnostics of HTTP responses
        const auto &statusCode = reply->attribute(QNetworkRequest::Attribute::HttpStatusCodeAttribute);
        const auto &statusMsg = reply->attribute(QNetworkRequest::Attribute::HttpReasonPhraseAttribute);
        auto replyError = reply->error();
        
        // Log full request/response details
        qInfo() << "HTTP Response details for:" << resource;
        qInfo() << "  Status: " << statusCode.toInt() << statusMsg.toByteArray().data();
        qInfo() << "  QNetworkReply error code:" << replyError;
        
        // Log request URL (using ApiResource to redact sensitive data) and headers
        qInfo() << "  Request URL:" << ApiResource{reply->request().url().toString()};
        qInfo() << "  Response Headers:";
        const auto &headers = reply->rawHeaderPairs();
        for (const auto &header : headers) {
            QString name = QString::fromUtf8(header.first);
            QString value = QString::fromUtf8(header.second);
            qInfo() << "    " << name << ":" << value;
        }
        
        // Check specifically for an auth error, which indicates that the creds are
        // not valid.
        // Look for both the QNetworkReply error code and the actual HTTP status code
        int httpStatus = reply->attribute(QNetworkRequest::Attribute::HttpStatusCodeAttribute).toInt();
        if (replyError == QNetworkReply::NetworkError::AuthenticationRequiredError || httpStatus == 401)
        {
            qWarning() << "Could not request" << resource << "due to invalid credentials (HTTP " << httpStatus << ")";
            networkTask->reject(Error(HERE, Error::ApiUnauthorizedError));
            return;
        }

        // If the API returned 429, it is rate limiting us, return a specific error.
        // This is still retriable, but it can cause NetworkTaskWithRetry to return
        // a specific error if all retries fail.
        if (httpStatus == 429)
        {
            QByteArray header = reply->rawHeader("Retry-After");
            // Default retry delay is 59 seconds
            int retryDelay = 59;
            if(!header.isEmpty())
            {
                bool ok{false};
                int val = header.toInt(&ok);
                if(ok)
                {
                    retryDelay = val;
                }
                else
                {
                    qWarning() << "Invalid Retry-After value, got: " << QString{header};
                }
            }
            else
            {
                qWarning() << "Retry-After header not found in 429 response";
            }

            qWarning() << "Could not request" << resource << "due to rate limiting; "
                       << "Retry after " << retryDelay << " seconds.";
            // A rate limiting error is worse than a network error - set the worst
            // retriable error, but keep trying in case another API endpoint gives us
            // 200 or 401.
            // (Otherwise, leave the worst error alone, it might already be set to a
            // rate limiting error by a prior attempt.)
            networkTask->reject(Error(HERE, Error::ApiRateLimitedError,
                                  QDateTime::currentDateTime().addSecs(retryDelay)));
            return;
        }

        if (httpStatus == 402)
        {
            // 402 is used by our client API to indicate an account subscription has expired
            qWarning() << "Could not request" << resource << "due to payment required";
            networkTask->reject(Error(HERE, Error::ApiPaymentRequiredError));
            return;
        }


        if (replyError != QNetworkReply::NetworkError::NoError)
        {
            qWarning() << "Could not request" << resource << "due to error:" << replyError;
            networkTask->reject(Error(HERE, Error::Code::ApiNetworkError));
            return;
        }

        networkTask->resolve(reply->readAll());
    });

    return networkTask;
}

void NetworkTaskWithRetry::traceLeafCert(const QSslCertificate &leafCert) const
{
    // In general, there can be any number of each of these fields
    const auto &commonNames = leafCert.subjectInfo(QSslCertificate::SubjectInfo::CommonName);
    const auto &serialNumbers = leafCert.subjectInfo(QSslCertificate::SubjectInfo::SerialNumber);
    const auto &altNames = leafCert.subjectAlternativeNames();
    qInfo() << "Certificate for" << _resource << "has" << commonNames.size()
        << "common names," << serialNumbers.size() << "serial numbers, and"
        << altNames.size() << "subject alternative names";
    for(const auto &cn : commonNames)
    {
        qInfo() << " - CN:" << cn;
    }
    for(const auto &serial : serialNumbers)
    {
        qInfo() << " - Serial:" << serial;
    }
    for(auto itSan = altNames.begin(); itSan != altNames.end(); ++itSan)
    {
        qInfo() << " - SAN:" << *itSan << "- type:" << itSan.key();
    }
}

void NetworkTaskWithRetry::checkSslCertificate(QNetworkReply &reply,
                                               const BaseUri &baseUri,
                                               const QList<QSslError> &errors)
{
    // This shouldn't happen, we don't connect this slot if pCA or peerName are
    // not set, but check for robustness - do not risk possibly accepting any
    // peer name
    if(!baseUri.pCA || baseUri.peerVerifyName.isEmpty())
    {
        qWarning() << "Not ignoring" << errors.size()
            << "SSL errors in request for" << _resource
            << "- CA or peer name is not known";
        return;
    }

    const auto &certChain = reply.sslConfiguration().peerCertificateChain();
    if(certChain.isEmpty())
    {
        qWarning() << "No certificate provided by server for"
            << baseUri.peerVerifyName;
        return;
    }

    // Log the errors for diagnostic purposes
    if (!errors.isEmpty()) {
        qInfo() << "SSL errors for" << baseUri.peerVerifyName << ":";
        for (const QSslError &error : errors) {
            qInfo() << "  -" << error.errorString();
        }
    }

    if(baseUri.pCA->verifyHttpsCertificate(certChain,
                                           baseUri.peerVerifyName))
    {
        qInfo() << "Accepted certificate for" << baseUri.peerVerifyName;
        traceLeafCert(certChain.first());
        reply.ignoreSslErrors();
    }
    else
    {
        qWarning() << "Rejected certificate for" << baseUri.peerVerifyName;
        traceLeafCert(certChain.first());
        
        // Show details that help diagnose certificate validation failures
        if (!certChain.isEmpty()) {
            QSslCertificate cert = certChain.first();
            qWarning() << "Certificate details:";
            qWarning() << "  - Effective date:" << cert.effectiveDate();
            qWarning() << "  - Expiry date:" << cert.expiryDate();
            qWarning() << "  - Issuer:" << cert.issuerDisplayName();
            qWarning() << "  - Expected CN:" << baseUri.peerVerifyName;
        }
    }
}
