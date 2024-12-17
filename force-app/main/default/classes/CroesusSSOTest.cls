/**
 * Created by benoitde on 2024-12-17.
 */

@IsTest
private class CroesusSSOTest {
    private class MockTokenResponse implements HttpCalloutMock {
        public HTTPResponse respond(HTTPRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            // A minimal token response JSON
            res.setBody('{"access_token": "test_access_token"}');
            return res;
        }
    }

    @testSetup
    static void setupTestData() {
        // Create a test user with a FederationIdentifier so that the queried CURRENT_USER has a value.
        User u = new User(
                ProfileId = [SELECT Id FROM Profile WHERE Name='Standard User' LIMIT 1].Id,
                UserRoleId = null,
                LastName = 'Test',
                FirstName = 'Federation',
                Alias = 'ffed',
                Email = 'federation_test_user@example.com',
                Username = 'federation_test_user@example.com.' + System.currentTimeMillis(),
                EmailEncodingKey = 'UTF-8',
                LocaleSidKey = 'en_US',
                LanguageLocaleKey = 'en_US',
                TimeZoneSidKey = 'America/New_York',
                FederationIdentifier = 'testFederationId'
        );
        insert u;
    }

    @IsTest
    static void testController() {
        PageReference pageRef = Page.croesussso;
        Test.setCurrentPage(pageRef);
        ApexPages.currentPage().getParameters().put('state', 'abc1234');
        ApexPages.currentPage().getParameters().put('callback', 'http://localhost');

        CroesusSSOController ctrl = new CroesusSSOController();
        PageReference redir = ctrl.urlRedirection();
        System.assert(redir.getRedirect());
    }

    @IsTest
    static void testAuthProvider() {
        User testUser = [SELECT Id FROM User WHERE FederationIdentifier = 'testFederationId' LIMIT 1];
        System.runAs(testUser) {
            // Prepare the authProviderConfiguration map with all required keys
            Map<String,String> authProviderConfiguration = new Map<String,String>{
                    'Certificate_Name__c' => 'MyCert',
                    'Token_Endpoint_URL__c' => 'callout:myEndpoint', // Endpoint key to trigger callout
                    'Client_ID__c' => 'myClientId',
                    'Client_Secret__c' => 'myClientSecret',
                    'Issuer__c' => 'myIssuer',
                    'VF_Redirection_Page_Name__c' => 'MyPage', // Must correspond to a VF page name
                    'Callback_URL__c' => 'https://my.callback.url',
                    'apikey__c' => 'myApiKey',
                    'apiroute__c' => 'myApiRoute'
            };

            // Set mock for HTTP callouts
            Test.setMock(HttpCalloutMock.class, new MockTokenResponse());

            // Instantiate the auth provider
            CroesusSSOAuthProvider provider = new CroesusSSOAuthProvider();

            Test.startTest();
            // Test getUserInfo
            Auth.AuthProviderTokenResponse tokenResponse = new Auth.AuthProviderTokenResponse('providerName', 'access_token_value', 'refresh_token_value', 'state_value');
            Auth.UserData userData = provider.getUserInfo(authProviderConfiguration, tokenResponse);
            System.assertEquals('testFederationId', userData.identifier, 'UserData identifier should match FederationIdentifier');
            System.assertEquals('federation_test_user@example.com', userData.email, 'Email should match the user email');

            // Test handleCallback
            Map<String, String> queryParams = new Map<String, String>{ 'state' => 'testState' };
            Auth.AuthProviderCallbackState callbackState = new Auth.AuthProviderCallbackState(null, null, queryParams);
            Auth.AuthProviderTokenResponse callbackResponse = provider.handleCallback(authProviderConfiguration, callbackState);
            System.assertNotEquals(null, callbackResponse.oauthToken, 'Access token should not be null');
            System.assertEquals('testState', callbackResponse.state, 'State should match the one provided in callbackState');

            // Test initiate
            // The initiate method returns a PageReference to a VF page with state and callback parameters
            String testStateString = 'someTestState';
            PageReference initPageRef = provider.initiate(authProviderConfiguration, testStateString);
            String initUrl = initPageRef.getUrl();
            System.assert(initUrl.contains('MyPage'), 'URL should contain the VF page name');
            System.assert(initUrl.contains(EncodingUtil.urlEncode(testStateString, 'UTF-8')), 'URL should include the encoded state parameter');
            System.assert(initUrl.contains(EncodingUtil.urlEncode('https://my.callback.url', 'UTF-8')), 'URL should include the encoded callback parameter');

            // Test refresh
            Auth.OAuthRefreshResult refreshResult = provider.refresh(authProviderConfiguration, 'oldRefreshToken');
            System.assertNotEquals(null, refreshResult.accessToken, 'Refreshed access token should not be null');
            System.assertNotEquals('oldRefreshToken', refreshResult.refreshToken, 'Refresh token should be newly generated and not match the old one');

            Test.stopTest();
        }
    }
}