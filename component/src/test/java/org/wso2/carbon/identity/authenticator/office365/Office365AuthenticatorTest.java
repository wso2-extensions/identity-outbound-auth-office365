/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

/**
 * Tests for {@link Office365Authenticator}.
 */
public class Office365AuthenticatorTest {

    private static final String IDP_CALLBACK_URL = "https://localhost:9443/commonauth";

    private Office365Authenticator authenticator;
    private HttpServletRequest request;
    private HttpServletResponse response;

    @BeforeMethod
    public void setUp() {

        authenticator = new Office365Authenticator();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        when(response.encodeRedirectURL(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @DataProvider
    public Object[][] additionalQueryParamsProvider() {

        Map<String, String> promptLogin = Collections.singletonMap("prompt", "login");
        return new Object[][]{
                // Authenticator param passed by the adaptive script.
                {"prompt=$authparam{prompt}", promptLogin, Collections.emptyMap(), "prompt=login&"},
                // No authenticator param: the placeholder resolves to an empty value.
                {"prompt=$authparam{prompt}", null, Collections.emptyMap(), "prompt=&"},
                // Request parameter placeholders keep working alongside authenticator params.
                {"prompt=$authparam{prompt}&login_hint=${login_hint}", promptLogin,
                        Collections.singletonMap("login_hint", new String[]{"alex@example.com"}),
                        "prompt=login&login_hint=alex@example.com&"},
                {"login_hint=${login_hint}", null,
                        Collections.singletonMap("login_hint", new String[]{"alex@example.com"}),
                        "login_hint=alex@example.com&"},
        };
    }

    @Test(dataProvider = "additionalQueryParamsProvider")
    public void testInitiateAuthenticationRequestResolvesAdditionalQueryParams(
            String additionalQueryParams, Map<String, String> authenticatorParams,
            Map<String, String[]> requestParams, String expectedQueryPrefix) throws Exception {

        AuthenticationContext context = new AuthenticationContext();
        context.setContextIdentifier("context-id");
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "client-id");
        authenticatorProperties.put(Office365AuthenticatorConstants.CALLBACK_URL, IDP_CALLBACK_URL);
        authenticatorProperties.put(Office365AuthenticatorConstants.ADDITIONAL_QUERY_PARAMS, additionalQueryParams);
        context.setAuthenticatorProperties(authenticatorProperties);
        if (authenticatorParams != null) {
            context.addAuthenticatorParams(Collections.singletonMap(
                    Office365AuthenticatorConstants.AUTHENTICATOR_NAME, new HashMap<>(authenticatorParams)));
        }
        when(request.getParameterMap()).thenReturn(requestParams);

        authenticator.initiateAuthenticationRequest(request, response, context);

        ArgumentCaptor<String> redirect = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(redirect.capture());
        String redirectUrl = redirect.getValue();
        assertEquals(redirectUrl.substring(0, redirectUrl.indexOf('?') + 1),
                Office365AuthenticatorConstants.office365_OAUTH_ENDPOINT + "?");
        assertEquals(redirectUrl.substring(redirectUrl.indexOf('?') + 1,
                redirectUrl.indexOf('?') + 1 + expectedQueryPrefix.length()), expectedQueryPrefix);
        assertFalse(redirectUrl.contains("$authparam"), "Unresolved $authparam placeholder in: " + redirectUrl);
        // The redirect must be a valid URI; an unresolved placeholder makes the authorize endpoint fail.
        new URI(redirectUrl);
    }
}
