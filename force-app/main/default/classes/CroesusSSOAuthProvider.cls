/**
 * Created by benoitde on 2023-09-29.
 */

public with sharing class CroesusSSOAuthProvider extends Auth.AuthProviderPluginClass {
    private static final User CURRENT_USER = [SELECT FederationIdentifier FROM User WHERE Id =: UserInfo.getUserId()];

    public static final String CERTIFICATE_NAME = Croesus_SSO__mdt.Certificate_Name__c.getDescribe().name;
    public static final String TOKEN_ENDPOINT_URL = Croesus_SSO__mdt.Token_Endpoint_URL__c.getDescribe().name;
    public static final String CLIENT_ID = Croesus_SSO__mdt.Client_ID__c.getDescribe().name;
    public static final String CLIENT_SECRET = Croesus_SSO__mdt.Client_Secret__c.getDescribe().name;
    public static final String ISSUER = Croesus_SSO__mdt.Issuer__c.getDescribe().name;
    public static final String VF_REDIRECTION_PAGE_NAME = Croesus_SSO__mdt.VF_Redirection_Page_Name__c.getDescribe().name;
    public static final String CALLBACK_URL = Croesus_SSO__mdt.Callback_URL__c.getDescribe().name;
    public static final String API_KEY = Croesus_SSO__mdt.apikey__c.getDescribe().name;
    public static final String API_ROUTE = Croesus_SSO__mdt.apiroute__c.getDescribe().name;

    public String getCustomMetadataType() {
        String metaName = Croesus_SSO__mdt.getSObjectType().getDescribe().name;
        return metaName;
    }

    public Auth.UserData getUserInfo(Map<String, String> authProviderConfiguration, Auth.AuthProviderTokenResponse response) {
        Auth.UserData user = new Auth.UserData(CURRENT_USER.FederationIdentifier, UserInfo.getFirstName(), UserInfo.getLastName(), UserInfo.getName(),
                UserInfo.getUserEmail(), null, CURRENT_USER.FederationIdentifier, UserInfo.getLocale(), 'Croesus', null, new Map<String, String>());
        return user;
    }

    public Auth.AuthProviderTokenResponse handleCallback(Map<String, String> authProviderConfiguration, Auth.AuthProviderCallbackState callbackState) {
        string token = getToken(authProviderConfiguration);

        String refreshToken = EncodingUtil.urlEncode(EncodingUtil.base64Encode(Crypto.generateAesKey(128)), 'utf-8');
        Auth.AuthProviderTokenResponse authResp = new Auth.AuthProviderTokenResponse('Croesus', token, refreshToken, callbackState.queryParameters.get('state'));
        return authResp;
    }

    public PageReference initiate(Map<String, String> authProviderConfiguration, String stateToPropagate) {
        String url = Url.getSalesforceBaseUrl().toExternalForm() + '/apex/' + authProviderConfiguration.get(VF_REDIRECTION_PAGE_NAME);
        url = url + '?state=' + EncodingUtil.urlEncode(stateToPropagate, 'utf-8') +
                '&callback=' + EncodingUtil.urlEncode(authProviderConfiguration.get(CALLBACK_URL), 'utf-8');
        return new PageReference(url);
    }

    public override Auth.OAuthRefreshResult refresh(Map<String,String> authProviderConfiguration, String refreshToken) {
        string token = getToken(authProviderConfiguration);

        refreshToken = EncodingUtil.urlEncode(EncodingUtil.base64Encode(Crypto.generateAesKey(128)), 'utf-8');
        Auth.OAuthRefreshResult result = new Auth.OAuthRefreshResult(token, refreshToken);

        return result;
    }

    private String getToken(Map<String,String> authProviderConfiguration) {
        Auth.JWT jwt = new Auth.JWT();
        jwt.setSub(CURRENT_USER.FederationIdentifier);
        jwt.setIss(authProviderConfiguration.get(ISSUER));
        Auth.JWS jws = new Auth.JWS(jwt, authProviderConfiguration.get(CERTIFICATE_NAME));

        Http http = new Http();
        HttpRequest req = new HttpRequest();
        req.setMethod('POST');
        String url = authProviderConfiguration.get(TOKEN_ENDPOINT_URL);
        Boolean first = true;
        String apikey = authProviderConfiguration.get(API_KEY);
        if ((null != apikey) && (apikey.length() > 0)) {
            if (first) {
                url += '?apikey=';
                first = false;
            } else {
                url += '&apikey=';
            }
            url += EncodingUtil.urlEncode(apikey,'UTF-8');
        }
        String apiroute = authProviderConfiguration.get(API_ROUTE);
        if ((null != apiroute) && (apiroute.length() > 0)) {
            if (first) {
                url += '?apiroute=';
                first = false;
            } else {
                url += '&apiroute=';
            }
            url += EncodingUtil.urlEncode(apiroute,'UTF-8');
        }
        req.setEndpoint(url);
        req.setHeader('Content-Type', 'application/x-www-form-urlencoded');

        String body='grant_type='+EncodingUtil.urlEncode('jwt-bearer','UTF-8');
        body=body + '&client_id='+EncodingUtil.urlEncode(authProviderConfiguration.get(CLIENT_ID),'UTF-8');
        body=body + '&client_secret='+EncodingUtil.urlEncode(authProviderConfiguration.get(CLIENT_SECRET),'UTF-8');
        if (!Test.isRunningTest()) {
            body=body + '&assertion='+EncodingUtil.urlEncode(jws.getCompactSerialization(),'UTF-8');
        }
        req.setBody(body);

        HttpResponse resp = http.send(req);
        Object o = JSON.deserializeUntyped(resp.getBody());
        Map<String, Object> m = (Map<String, Object>)o;
        String token = (String)m.get('access_token');

        return token;
    }
}