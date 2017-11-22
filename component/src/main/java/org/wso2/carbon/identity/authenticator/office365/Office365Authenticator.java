/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.office365;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Office365.
 *
 * @since 1.0.1
 */
public class Office365Authenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(Office365Authenticator.class);

    /**
     * Get Outlook authorization endpoint.
     *
     * @param authenticatorProperties Office365 authenticatorProperties.
     * @return Office365 oauth endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return Office365AuthenticatorConstants.office365_OAUTH_ENDPOINT;
    }

    /**
     * Get Outlook token endpoint.
     *
     * @param authenticatorProperties Office365 authenticatorProperties.
     * @return Office365 token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return Office365AuthenticatorConstants.office365_TOKEN_ENDPOINT;
    }

    /**
     * Get Outlook user info endpoint.
     *
     * @param token                   OAuthClientResponse.
     * @param authenticatorProperties Office365 authenticatorProperties.
     * @return Office365 user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return Office365AuthenticatorConstants.office365_USERINFO_ENDPOINT;
    }

    /**
     * Check ID token in Outlook OAuth.
     *
     * @param authenticatorProperties Office365 authenticatorProperties.
     * @return false.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator.
     */
    @Override
    public String getFriendlyName() {
        return Office365AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator.
     */
    @Override
    public String getName() {
        return Office365AuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Office365 client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Office365 client secret value");
        clientSecret.setDisplayOrder(1);
        configProperties.add(clientSecret);

        Property redirectUri = new Property();
        redirectUri.setDisplayName("Callback Url");
        redirectUri.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        clientId.setRequired(true);
        redirectUri.setDescription("Enter value corresponding to callback url.");
        redirectUri.setDisplayOrder(2);
        configProperties.add(redirectUri);

        return configProperties;
    }

    /**
     * Get the Context identifier sent with the request.
     *
     * @param request HttpServletRequest.
     * @return A randomly generated non-reused value.
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(Office365AuthenticatorConstants.STATE);
    }

    /**
     * Check whether the authentication or logout request can be handled by the authenticator.
     *
     * @param arg0 HttpServletRequest.
     * @return true.
     */
    @Override
    public boolean canHandle(HttpServletRequest arg0) {
        return true;
    }

    /**
     * Authenticator flow process.
     *
     * @param request  The request.
     * @param response The response.
     * @param context  The authentication context.
     * @return Authentication flow status.
     * @throws AuthenticationFailedException On error while authenticating.
     * @throws LogoutFailedException         On error while login.
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and doing complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        if (StringUtils.isNotEmpty(request.getParameter(Office365AuthenticatorConstants.CODE))) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        initiateAuthenticationRequest(request, response, context);
        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Initiate the authentication request.
     *
     * @param request  The request.
     * @param response The response.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException On error while authenticating.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String redirectUri = authenticatorProperties.get(Office365AuthenticatorConstants.CALLBACK_URL);
        String loginPage = getAuthorizationServerEndpoint(context.getAuthenticatorProperties());
        String queryParams = Office365AuthenticatorConstants.STATE + "=" + context.getContextIdentifier();
        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + "?" + queryParams + "&" +
                    Office365AuthenticatorConstants.CLIENT_ID + "=" + clientId + "&" +
                    Office365AuthenticatorConstants.RESPONSE_TYPE + "=" +
                    OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE + "&" +
                    Office365AuthenticatorConstants.REDIRECT_URI + "=" + redirectUri + "&" +
                    Office365AuthenticatorConstants.Resource + "=" + Office365AuthenticatorConstants.OFFICE365_RESOURCE));
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while redirecting", e);
        }
    }

    /**
     * Process the response of the office365 end-point.
     *
     * @param request  The request.
     * @param response The response.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException On error while authenticating.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            String callbackUrl = getCallbackUrl(authenticatorProperties);
            OAuthAuthzResponse authorizationResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authorizationResponse.getCode();
            OAuthClientRequest accessRequest =
                    getAccessRequest(tokenEndPoint, clientId, code, clientSecret, callbackUrl);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessRequest);
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }
            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);
            String json;
            try {
                json = fetchUserInfo(Office365AuthenticatorConstants.office365_USERINFO_ENDPOINT,
                        oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN));
            } catch (ApplicationAuthenticatorException e) {
                throw new AuthenticationFailedException("Error while getting user details", e);
            }
            JSONObject obj = new JSONObject(json);
            Map<ClaimMapping, String> claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
            String id = claims.get(ClaimMapping.build(Office365AuthenticatorConstants.ID,
                    Office365AuthenticatorConstants.ID, null, false));
            AuthenticatedUser authenticatedUserObj =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier((String) obj.
                            get(Office365AuthenticatorConstants.ID));
            authenticatedUserObj.setAuthenticatedSubjectIdentifier(id);
            authenticatedUserObj.setUserAttributes(claims);
            context.setSubject(authenticatedUserObj);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    /**
     * Get the oauth response.
     *
     * @param oAuthClient   OAuthClient.
     * @param accessRequest Access request to get accessToken.
     * @return Response OAuthClientResponse.
     * @throws AuthenticationFailedException On error while authenticating.
     */
    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {
        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new AuthenticationFailedException("Exception while requesting access token " + e.getMessage(), e);
        }
        return oAuthResponse;
    }

    /**
     * Get the access request.
     *
     * @param tokenEndPoint Office365 authorize endpoint URL.
     * @param clientId      The client ID of the client application that is registered in Azure AD.
     * @param code          Authorization code to be used to obtain the access token.
     * @param clientSecret  The value of the key that contains the client password.
     * @param callbackUrl   Specifies the reply URL of the application.
     * @return Response OAuthClientRequest.
     * @throws AuthenticationFailedException On error while authenticating.
     */
    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
                                                String callbackUrl) throws AuthenticationFailedException {
        OAuthClientRequest accessRequest;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setCode(code)
                    .setRedirectURI(callbackUrl)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException("Exception while building request for request access token " +
                    e.getMessage(), e);
        }
        return accessRequest;
    }

    /**
     * Get office365 user details.
     *
     * @param url         User info endpoint.
     * @param accessToken Access token.
     * @return User info details.
     * @throws IOException On error while making connection.
     */
    protected String fetchUserInfo(String url, String accessToken) throws ApplicationAuthenticatorException {

        if (log.isDebugEnabled()) {
            log.debug("Claim URL: " + url);
        }
        if (url == null) {
            return StringUtils.EMPTY;
        }
        StringBuilder jsonResponseCollector = new StringBuilder();
        BufferedReader bufferedReader = null;
        try {
            URL obj = new URL(url);
            HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
            urlConnection.setRequestMethod(Office365AuthenticatorConstants.HTTP_GET);
            urlConnection.setRequestProperty(Office365AuthenticatorConstants.HEADER_ACCEPT,
                    Office365AuthenticatorConstants.ODATA_ACCEPT_HEADER);
            urlConnection.setRequestProperty(Office365AuthenticatorConstants.Authorization,
                    Office365AuthenticatorConstants.BEARER + accessToken);
            bufferedReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String inputLine = bufferedReader.readLine();
            while (inputLine != null) {
                jsonResponseCollector.append(inputLine).append("\n");
                inputLine = bufferedReader.readLine();
            }
        } catch (MalformedURLException e) {
            throw new ApplicationAuthenticatorException("MalformedURLException while generating the user info URL: "
                    + url, e);
        } catch (ProtocolException e) {
            throw new ApplicationAuthenticatorException("ProtocolException while setting the request method: " +
                    Office365AuthenticatorConstants.HTTP_GET + " for the URL: " + url, e);
        } catch (IOException e) {
            throw new ApplicationAuthenticatorException("Error when reading the response from " + url +
                    "to update user claims", e);
        } finally {
            IdentityIOStreamUtils.closeReader(bufferedReader);
        }
        if (log.isDebugEnabled()) {
            log.debug("Receiving the response for the User info: " + jsonResponseCollector.toString());
        }
        return jsonResponseCollector.toString();
    }
}