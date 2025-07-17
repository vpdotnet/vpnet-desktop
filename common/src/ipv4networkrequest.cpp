#include "common.h"
#line SOURCE_FILE("ipv4networkrequest.cpp")

#include "ipv4networkrequest.h"

IPv4NetworkRequest::IPv4NetworkRequest(QObject *parent) : QObject(parent)
{
    manager = new QNetworkAccessManager(this);
    connect(manager, &QNetworkAccessManager::finished, this, &IPv4NetworkRequest::handleNetworkReply);
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

    qDebug() << "Sending" << originalUrl.scheme().toUpper() << "request to:" << request.url().toString()
             << "with Host header:" << originalUrl.host();

    // Send the GET request
    manager->get(request);
}

void IPv4NetworkRequest::handleNetworkReply(QNetworkReply *reply)
{
    if (reply->error() != QNetworkReply::NoError) {
        qWarning() << "Network request failed:" << reply->errorString();
    } else {
        qDebug() << "Network request successful. Status:" 
                 << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    }

    // Forward the reply to the caller
    emit finished(reply);
    // The caller is responsible for deleting the reply with reply->deleteLater()
}