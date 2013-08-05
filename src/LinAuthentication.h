// LinAuthentication.h

// LinkedIn authentication using OAuth 2.0.

#ifndef __LinkedinCpp_LinAuthentication_h__ 
#define __LinkedinCpp_LinAuthentication_h__ 

#include <QWebView>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QUuid>
#include <QJsonDocument>
#include <QJsonObject>
#include <memory>

namespace LinAuthParameters
{
    // Value is always - "code".
    const QString kLinAuthResponseType = "response_type";
    // Value of your API Key given when you registered your application with LinkedIn.
    const QString kLinAuthClientId = "client_id";
    // Value of your secret key given when you registered your application with LinkedIn.
    const QString kLinAuthClientSecret = "client_secret";
    // Use it to specify a list of member permissions that you need and these will be shown to 
    // the user on LinkedIn's authorization form.
    const QString kLinAuthScope = "scope";
    // A long unique string value of your choice that is hard to guess. Used to prevent cross-site request forgery attacks.
    const QString kLinAuthState = "state";
    const QString kLinStateError = "state_error";
    const QString kLinStateErrorDescription = "The value of 'state' was changed.";
    // URI in your app where users will be sent after authorization.
    const QString kLinAuthRedirectURI = "redirect_uri";
    // Authorization code
    const QString kLinAuthCode = "code";
    const QString kLinAuthError = "error";
    const QString kLinAuthErrorDescription = "error_description";
    const QString kLinAuthGrantType = "grant_type";
    // The value is the number of seconds from now that access token will expire.
    const QString kLinJsonExpiresIn = "expires_in";
    const QString kLinJsonAccessToken = "access_token";

    // List of member permissions.
    enum kMemberPermissions
    {
        kMPBasicProfile = 1 << 0,
        kMPNetwork      = 1 << 1,
        kMPGroups       = 1 << 2,
        kMPFullProfile  = 1 << 3,
        kMPContactInfo  = 1 << 4,
        kMPMessages     = 1 << 5,
        kMPEmailAddress = 1 << 6,
        kMPNus          = 1 << 7,

        kMPEND          = 1 << 8
    };

    QString kMemberPermissionsNames[];

    const QString kLinAuthDialogUrl = "https://www.linkedin.com/uas/oauth2/authorization";
    const QString kLinAuthAccessTokenUrl = "https://www.linkedin.com/uas/oauth2/accessToken";
}

// Custom web-page which retrieve authorization code from url.
class AuthWebPage : public QWebPage 
{
    Q_OBJECT

signals:
    void sigAuthCodeDelivered(const QString& authorizationCode, const QString& authorizationState,
                              const QString& redirectHost);
    // errorCode value can be one of the HTTP status code OR
    // one of the QNetworkReply::NetworkError set of error code OR
    // one of the LinkedIn defined code, for example - access_denied, etc.
    void sigAuthError(const QString& errorCode, const QString& errorDescription);

public:
    AuthWebPage(QObject* parent = nullptr);
    void setRedirectHost(const QString& redirectHost);

protected:
    // Retrieve authorization code when redirecting to - YOUR_REDIRECT_URI/?code=AUTHORIZATION_CODE&state=STATE
    bool acceptNavigationRequest(QWebFrame* frame, const QNetworkRequest& request, NavigationType type);

private:
    QString mRedirectHost;
};

class LinAuthentication : public QObject
{
    Q_OBJECT

signals:
    void sigAuthTokenDelivered(const QString& accessToken, const double expiresIn);
    void sigAuthError(const QString& errorCode, const QString& errorDescription);

public:
    // QWebView using for redirecting to LinkedIn's authorization dialog.
    LinAuthentication(QWebView* webView);
    virtual ~LinAuthentication();

    // API/Secret Key given when you registered your application with LinkedIn.
    // clientId - API Key.
    // clientSecret - Secret Key.
    // redirectHost - URI in your app where users will be sent after authorization. 
    // memberPermissions - Permissions you want users to grant your application.
    void authenticate(const QString& clientId, const QString& clientSecret, const QString& redirectHost, unsigned int memberPermissions);

private:
    QUrl buildAuthDialogUrl(const QString& clientId, const QString& redirectHost, unsigned int memberPermissions);
    QList<QString> membersPermissionsToString(unsigned int memberPermissions);
    QString generateState();

private slots:
    void on_sigAuthCodeDelivered(const QString& authorizationCode, const QString& authorizationState,
                                 const QString& redirectHost);
    void on_sigAuthError(const QString& errorCode, const QString& errorDescription);
    void on_sigTokenRequestFinished(QNetworkReply* networkReply);

private:
    QWebView* mAuthWebView;
    QWebPage* mOrigWebPage;
    std::unique_ptr<QNetworkAccessManager> mNetAccessManager;
    std::unique_ptr<AuthWebPage> mAuthWebPage;

    QString mAuthState;
    QString mClientId;
    QString mClientSecret;
};


#endif // _LinkedinCpp_LinAuthentication_h__
