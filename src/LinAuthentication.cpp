// LinAuthentication.cpp

// LinkedIn authentication using OAuth 2.0.

#include "LinAuthentication.h"

QString LinAuthParameters::kMemberPermissionsNames[] =
{
    "r_basicprofile",
    "r_network",
    "rw_groups",
    "r_fullprofile",
    "r_contactinfo",
    "w_messages",
    "r_emailaddress",
    "rw_nus"
};


AuthWebPage::AuthWebPage(QObject* parent) : QWebPage(parent)
{}

void AuthWebPage::setRedirectHost(const QString& redirectHost)
{
    Q_ASSERT(!redirectHost.isEmpty());

    mRedirectHost = redirectHost;
}

bool AuthWebPage::acceptNavigationRequest(QWebFrame* frame, const QNetworkRequest& request, NavigationType type)
{
    Q_ASSERT(frame);

    if (request.url().host() == QUrl(mRedirectHost).host())
    {
        Q_ASSERT(request.url().hasQuery());

        QUrlQuery urlQuery(request.url());

        // Check if operation succeeded and we got a code.
        if (urlQuery.hasQueryItem(LinAuthParameters::kLinAuthCode))
        {
            Q_ASSERT(urlQuery.hasQueryItem(LinAuthParameters::kLinAuthState));

            QString code = urlQuery.queryItemValue(LinAuthParameters::kLinAuthCode);
            Q_ASSERT(!code.isEmpty());
            QString state = urlQuery.queryItemValue(LinAuthParameters::kLinAuthState);
            Q_ASSERT(!state.isEmpty());

            emit sigAuthCodeDelivered(code, state, mRedirectHost);
        }
        else if (urlQuery.hasQueryItem(LinAuthParameters::kLinAuthError))
        {
            Q_ASSERT(urlQuery.hasQueryItem(LinAuthParameters::kLinAuthErrorDescription));

            QString errorCode = urlQuery.queryItemValue(LinAuthParameters::kLinAuthError);
            Q_ASSERT(!errorCode.isEmpty());
            QString errorDesc = urlQuery.queryItemValue(LinAuthParameters::kLinAuthErrorDescription);
            Q_ASSERT(!errorDesc.isEmpty());

            emit sigAuthError(errorCode, errorDesc);
        }
    }

    return QWebPage::acceptNavigationRequest(frame, request, type);
}


LinAuthentication::LinAuthentication(QWebView* webView) : QObject(nullptr),
                                                          mAuthWebView(webView),
                                                          mOrigWebPage(webView->page()),
                                                          mNetAccessManager(std::unique_ptr<QNetworkAccessManager>(new QNetworkAccessManager())),
                                                          mAuthWebPage(std::unique_ptr<AuthWebPage>(new AuthWebPage(webView)))
{
    mAuthWebView->setPage(mAuthWebPage.get());
}

LinAuthentication::~LinAuthentication()
{
    Q_ASSERT(mOrigWebPage);

    mAuthWebView->setPage(mOrigWebPage);
}

void LinAuthentication::authenticate(const QString& clientId, const QString& clientSecret, const QString& redirectHost, unsigned int memberPermissions)
{
    Q_ASSERT(!clientId.isEmpty());
    Q_ASSERT(!clientSecret.isEmpty());
    Q_ASSERT(!redirectHost.isEmpty());
    Q_ASSERT(memberPermissions);
   
    mAuthWebPage->setRedirectHost(redirectHost);

    bool status = connect(mAuthWebPage.get(), SIGNAL(sigAuthCodeDelivered(const QString&, const QString&,const QString&)), this,
                          SLOT(on_sigAuthCodeDelivered(const QString&, const QString&, const QString&)));
    Q_ASSERT(status);
    
    status = connect(mAuthWebPage.get(), SIGNAL(sigAuthError(const QString&, const QString&)), this,
                     SLOT(on_sigAuthError(const QString&, const QString&)));
    Q_ASSERT(status);

    QUrl authDlgUrl = buildAuthDialogUrl(clientId, redirectHost, memberPermissions);
    Q_ASSERT(!authDlgUrl.isEmpty());

    QUrlQuery urlQuery(authDlgUrl);
    Q_ASSERT(urlQuery.hasQueryItem(LinAuthParameters::kLinAuthState));

    mAuthState = urlQuery.queryItemValue(LinAuthParameters::kLinAuthState);
    mClientId = clientId;
    mClientSecret = clientSecret;

    mAuthWebView->load(authDlgUrl);
}

QUrl LinAuthentication::buildAuthDialogUrl(const QString& clientId, const QString& redirectHost, unsigned int memberPermissions)
{
    Q_ASSERT(!clientId.isEmpty());
    Q_ASSERT(!redirectHost.isEmpty());
    Q_ASSERT(memberPermissions);

    QList<QString> permList = membersPermissionsToString(memberPermissions);
    Q_ASSERT(!permList.isEmpty());

    QList<QString>::const_iterator it = permList.constBegin();
    QString perms = *it++;
    for(; it != permList.constEnd(); it++)
    {
        perms += ("%20" + *it);
    }
   
    QUrl authDlgUrl(LinAuthParameters::kLinAuthDialogUrl);
    QUrlQuery urlQuery;
    urlQuery.addQueryItem(LinAuthParameters::kLinAuthResponseType, "code");
    urlQuery.addQueryItem(LinAuthParameters::kLinAuthClientId, clientId);
    urlQuery.addQueryItem(LinAuthParameters::kLinAuthScope, perms);
    urlQuery.addQueryItem(LinAuthParameters::kLinAuthState, generateState());
    urlQuery.addQueryItem(LinAuthParameters::kLinAuthRedirectURI, redirectHost);
    authDlgUrl.setQuery(urlQuery);

    return authDlgUrl;
}

QList<QString> LinAuthentication::membersPermissionsToString(unsigned int memberPermissions)
{
    using LinAuthParameters::kMemberPermissions;

    Q_ASSERT(memberPermissions);

    QList<QString> permNames;

    for (unsigned int perm = kMemberPermissions::kMPBasicProfile, i = 0; perm < kMemberPermissions::kMPEND; perm <<= 1, i++)
    {
        if (memberPermissions & perm)
            permNames.push_back(LinAuthParameters::kMemberPermissionsNames[i]);
    }

    return permNames;
}

QString LinAuthentication::generateState()
{
    QUuid uuid = QUuid::createUuid();
    Q_ASSERT(!uuid.isNull());

    return QString(uuid.toByteArray().toBase64());
}

void LinAuthentication::on_sigAuthCodeDelivered(const QString& authorizationCode, const QString& authorizationState, 
                                                const QString& redirectHost)
{
    Q_ASSERT(!authorizationCode.isEmpty());
    Q_ASSERT(!authorizationState.isEmpty());

    if (mAuthState != authorizationState)
        emit sigAuthError(LinAuthParameters::kLinStateError, LinAuthParameters::kLinAuthErrorDescription);
    else
    {
        QUrlQuery urlQuery(LinAuthParameters::kLinAuthAccessTokenUrl);
        urlQuery.addQueryItem(LinAuthParameters::kLinAuthGrantType, "authorization_code");
        urlQuery.addQueryItem(LinAuthParameters::kLinAuthCode, authorizationCode);
        urlQuery.addQueryItem(LinAuthParameters::kLinAuthRedirectURI, redirectHost);
        urlQuery.addQueryItem(LinAuthParameters::kLinAuthClientId, mClientId);
        urlQuery.addQueryItem(LinAuthParameters::kLinAuthClientSecret, mClientSecret);

        QUrl url;
        url.setQuery(urlQuery);
        QByteArray encodedData = url.toEncoded();
        Q_ASSERT(!encodedData.isEmpty());

        QUrl tokenUrl(LinAuthParameters::kLinAuthAccessTokenUrl);
        QNetworkRequest tokenRequest(tokenUrl);
        tokenRequest.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

        bool status = connect(mNetAccessManager.get(), SIGNAL(finished(QNetworkReply*)), this, SLOT(on_sigTokenRequestFinished(QNetworkReply*)));
        Q_ASSERT(status);

        mNetAccessManager->post(tokenRequest, encodedData);
    }
}

void LinAuthentication::on_sigAuthError(const QString& errorCode, const QString& errorDescription)
{
    emit sigAuthError(errorCode, errorDescription);
}

void LinAuthentication::on_sigTokenRequestFinished(QNetworkReply* networkReply)
{
    if (QNetworkReply::NetworkError::NoError == networkReply->error())
    {
        QString strJson(networkReply->readAll());
        Q_ASSERT(!strJson.isEmpty());

        QJsonDocument jsonDoc = QJsonDocument::fromJson(strJson.toUtf8());
        Q_ASSERT(!jsonDoc.isNull());

        QJsonObject jsonObj = jsonDoc.object();
        double expiresIn = jsonObj[LinAuthParameters::kLinJsonExpiresIn].toDouble();
        QString accessToken = jsonObj[LinAuthParameters::kLinJsonAccessToken].toString();

        Q_ASSERT(expiresIn > 0);
        Q_ASSERT(!accessToken.isEmpty());

        emit sigAuthTokenDelivered(accessToken, expiresIn);
    }
    else
        emit sigAuthError(QString::number(networkReply->error()), "");
}