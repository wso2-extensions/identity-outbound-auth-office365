/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.authenticator.office365;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.doNothing;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, IdentityUtil.class, Office365Authenticator.class, OAuthClientRequest.class})
public class Office365AuthenticatorTest {

    @Mock
    Office365Authenticator mockOfficeAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private OAuthAuthzResponse oAuthAuthzResponse;

    @Mock
    private OAuthClientResponse oAuthClientResponse;

    @Spy
    private AuthenticationContext context;

    @Spy
    private Office365Authenticator spy;

    private Office365Authenticator office365Authenticator;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {
        office365Authenticator = new Office365Authenticator();
        initMocks(this);
    }

    @Test(description = "Test case for canHandle method true.")
    public void testCanHandle() {
        Mockito.when(httpServletRequest.getParameter(Office365AuthenticatorConstants.CODE))
                .thenReturn("dummy-code");
        Mockito.when(httpServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE))
                .thenReturn("test-state");
        Mockito.doReturn(Office365AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME).when(spy)
                .getLoginType(httpServletRequest);
        Assert.assertEquals(true, spy.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for getLoginType method.")
    public void testGetLoginType() {
        Mockito.when(httpServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE))
                .thenReturn("test-state,login-type");
        Assert.assertEquals(office365Authenticator.getLoginType(httpServletRequest), "login-type");
    }

    @Test(description = "Test case for process() method for logout request.")
    public void testProcessForLogoutRequest() throws AuthenticationFailedException, LogoutFailedException {
        Mockito.when(context.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = office365Authenticator
                .process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for process() method for authentication incomplete flow .")
    public void testProcessIncomplete() throws AuthenticationFailedException, LogoutFailedException {
        Mockito.when(httpServletRequest.getParameter(Office365AuthenticatorConstants.CODE))
                .thenReturn("");
        Mockito.when(httpServletRequest.getParameter(Office365AuthenticatorConstants.OAUTH2_PARAM_ERROR))
                .thenReturn("");
        doNothing().when(spy).initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        AuthenticatorFlowStatus status = office365Authenticator
                .process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method for authentication complete flow .")
    public void testProcessComplete() throws AuthenticationFailedException, LogoutFailedException {
        Mockito.when(httpServletRequest.getParameter(Office365AuthenticatorConstants.CODE))
                .thenReturn("dummy-code");
        doNothing().when(spy).processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "test process authentication response method", expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthenticationResponse() throws Exception {
        Office365Authenticator spyAuthenticator = PowerMockito.spy(new Office365Authenticator());
        Mockito.when(httpServletRequest.getParameter(Office365AuthenticatorConstants.OAUTH2_PARAM_ERROR))
                .thenReturn(null);
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(httpServletRequest)).thenReturn(oAuthAuthzResponse);
        PowerMockito.doReturn(oAuthClientResponse)
                .when(spyAuthenticator, "getOauthResponse", Mockito.any(OAuthClient.class),
                        Mockito.any(OAuthClientRequest.class));
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "test getAccessRequest method")
    public void testGetAccessRequest() throws Exception {
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString()))
                .thenReturn(new OAuthClientRequest.TokenRequestBuilder("/token"));
        OAuthClientRequest getAccessRequest = Whitebox
                .invokeMethod(office365Authenticator, "getAccessRequest", "/token", "dummy-clientId", "dummy-code",
                        "dummy-secret", "/callback");
        Assert.assertNotNull(getAccessRequest);
        Assert.assertEquals(getAccessRequest.getLocationUri(), "/token");
    }

}
