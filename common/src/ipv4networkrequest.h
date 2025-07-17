#ifndef IPV4NETWORKREQUEST_H
#define IPV4NETWORKREQUEST_H

#include "common.h"

#include <QObject>
#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QHostInfo>
#include <QAbstractSocket>
#include <QSslConfiguration>
#include <QDebug>

// This class provides a way to make HTTP/HTTPS requests that explicitly use IPv4,
// even on systems that might prefer IPv6 by default.
class COMMON_EXPORT IPv4NetworkRequest : public QObject
{
    Q_OBJECT

public:
    explicit IPv4NetworkRequest(QObject *parent = nullptr);
    ~IPv4NetworkRequest();

    // Make a GET request forcing IPv4 resolution
    void get(const QUrl& url);

signals:
    void finished(QNetworkReply *reply);
    void error(const QString& errorMessage);

private slots:
    void handleHostLookup(const QHostInfo &hostInfo);
    void handleNetworkReply(QNetworkReply *reply);

private:
    QNetworkAccessManager *manager;
    QUrl originalUrl;
};

// Register our class for Q_DECLARE_METATYPE
Q_DECLARE_METATYPE(IPv4NetworkRequest*)

#endif // IPV4NETWORKREQUEST_H