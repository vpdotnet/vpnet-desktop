#include "common.h"
#line SOURCE_FILE("ipv4networkrequest.cpp")

#include "ipv4networkrequest.h"
#include <QSslError>

IPv4NetworkRequest::IPv4NetworkRequest(QObject *parent) : QObject(parent)
{
    manager = new QNetworkAccessManager(this);
    connect(manager, &QNetworkAccessManager::finished, this, &IPv4NetworkRequest::handleNetworkReply);
    connect(manager, &QNetworkAccessManager::sslErrors, this, &IPv4NetworkRequest::handleSslErrors);
}

IPv4NetworkRequest::~IPv4NetworkRequest()
{
    // QNetworkAccessManager will be deleted automatically as a child QObject
}

void IPv4NetworkRequest::get(const QUrl& url)
{
    originalUrl = url;
    QString host = originalUrl.host();

    if (host.isEmpty()) {
        emit error("Invalid URL: No host specified.");
        return;
    }

    // Begin asynchronous hostname lookup
    QHostInfo::lookupHost(host, this, SLOT(handleHostLookup(QHostInfo)));
}

void IPv4NetworkRequest::handleHostLookup(const QHostInfo &hostInfo)
{
    if (hostInfo.error() != QHostInfo::NoError) {
        QString errorMsg = QString("Host lookup failed for %1: %2")
                             .arg(hostInfo.lookupId())
                             .arg(hostInfo.errorString());
        qWarning() << errorMsg;
        emit error(errorMsg);
        return;
    }

    // Find the first IPv4 address in the lookup results
    QHostAddress ipv4Address;
    for (const QHostAddress &address : hostInfo.addresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) {
            ipv4Address = address;
            qDebug() << "Found IPv4 address for" << hostInfo.hostName() << ":" << ipv4Address.toString();
            break;
        }
    }

    if (ipv4Address.isNull()) {
        QString errorMsg = QString("No IPv4 address found for host: %1").arg(hostInfo.hostName());
        qWarning() << errorMsg;
        emit error(errorMsg);
        return;
    }

    // Construct URL using the IPv4 address instead of hostname
    QUrl ipUrl = originalUrl;
    ipUrl.setHost(ipv4Address.toString());

    // Create request with the IP-based URL
    QNetworkRequest request(ipUrl);

    // Temporarily disable HTTP/2 to test if HTTP/1.1 resolves the 403 error
    // (HTTP/2 to IP addresses with correct SNI/Host works fine with curl, so the issue
    // may be specific to how Qt's HTTP/2 implementation is constructing the request)
    request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);

    // Set Host header to the original hostname (required for virtual hosting)
    request.setRawHeader("Host", originalUrl.host().toUtf8());

    // Configure SSL for HTTPS connections
    if (originalUrl.scheme().compare("https", Qt::CaseInsensitive) == 0) {
        QSslConfiguration sslConfig = request.sslConfiguration();
        sslConfig.setPeerVerifyMode(QSslSocket::VerifyPeer);
        request.setSslConfiguration(sslConfig);
        request.setPeerVerifyName(originalUrl.host()); // Set hostname for SNI & cert validation
        qDebug() << "HTTPS: Set PeerVerifyName for SNI/validation to:" << originalUrl.host();
    }

    qDebug() << "Sending GET request to:" << request.url().toString();
    qDebug() << "  Host header:" << QString::fromUtf8(request.rawHeader("Host"));
    qDebug() << "  All headers:";
    for (const auto &header : request.rawHeaderList()) {
        qDebug() << "    " << QString::fromUtf8(header) << ":" << QString::fromUtf8(request.rawHeader(header));
    }

    // Send the GET request
    manager->get(request);
}

void IPv4NetworkRequest::handleNetworkReply(QNetworkReply *reply)
{
    if (reply->error() != QNetworkReply::NoError) {
        qWarning() << "Network request failed:" << reply->errorString();
        qWarning() << "  Request URL:" << reply->request().url().toString();
        qWarning() << "  HTTP Status:" << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        qWarning() << "  QNetworkReply error code:" << reply->error();

        // Log response headers
        qWarning() << "  Response headers:";
        for (const auto &header : reply->rawHeaderList()) {
            qWarning() << "    " << QString::fromUtf8(header) << ":" << QString::fromUtf8(reply->rawHeader(header));
        }

        // Log response body to understand why (use peek to not consume the buffer)
        QByteArray responseBody = reply->peek(4096);
        if (!responseBody.isEmpty()) {
            qWarning() << "  Response body:" << QString::fromUtf8(responseBody);
        }

        // Check if there were SSL errors captured
        if (!_sslErrors.isEmpty()) {
            qWarning() << "  SSL Errors:";
            for (const QSslError &sslError : _sslErrors) {
                qWarning() << "    -" << sslError.errorString();
            }
        }
    } else {
        qDebug() << "Network request successful. Status:"
                 << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    }

    // Clear SSL errors for next request
    _sslErrors.clear();

    // Forward the reply to the caller
    emit finished(reply);
    // The caller is responsible for deleting the reply with reply->deleteLater()
}

void IPv4NetworkRequest::handleSslErrors(QNetworkReply *reply, const QList<QSslError> &errors)
{
    // Store SSL errors so they can be logged in handleNetworkReply
    _sslErrors = errors;

    qWarning() << "SSL errors occurred for request:" << reply->request().url().toString();
    for (const QSslError &error : errors) {
        qWarning() << "  SSL Error:" << error.errorString();
        qWarning() << "    Certificate:" << error.certificate().subjectInfo(QSslCertificate::CommonName);
    }
}