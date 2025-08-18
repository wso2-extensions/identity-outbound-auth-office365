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
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Authenticator of Outlook
 */
public class Office365Authenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static final String EQUAL = "=";
    private static final String QUERY_PARAM_SEPARATOR = "&";
    private static final String MULTI_OPTION_URI = "multiOptionURI";
    private static final Log log = LogFactory.getLog(Office365Authenticator.class);

    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static Pattern pattern = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX);

    /**
     * Get Outlook authorization endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return Office365AuthenticatorConstants.office365_OAUTH_ENDPOINT;
    }

    /**
     * Get Outlook token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return Office365AuthenticatorConstants.office365_TOKEN_ENDPOINT;
    }

    /**
     * Get Outlook user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return Office365AuthenticatorConstants.office365_USERINFO_ENDPOINT;
    }

    /**
     * Check ID token in Outlook OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return Office365AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return Office365AuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get Configuration Properties
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

        Property requestedQueryParam = new Property();
        requestedQueryParam.setDisplayName("Additional Query Parameters");
        requestedQueryParam.setName(Office365AuthenticatorConstants.ADDITIONAL_QUERY_PARAMS);
        requestedQueryParam.setValue("username={username}&login_hint={username}");
        requestedQueryParam.setDescription("Additional query parameters. e.g: login_hint=email@example.com");
        requestedQueryParam.setDisplayOrder(3);
        configProperties.add(requestedQueryParam);

        return configProperties;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
    }

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (request.getParameter(Office365AuthenticatorConstants.CODE) != null &&
                request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE) != null &&
                Office365AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME.equals(getLoginType(request))) {
            return true;
        } else if (request.getParameter(Office365AuthenticatorConstants.OAUTH2_PARAM_ERROR) != null) {
            return true;
        }
        return false;
    }

    /**
     * Return the claim dialect URI.
     */
    @Override
    public String getClaimDialectURI() {

        return null;
    }

    protected String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    /**
     * Handle error response when unauthorized the registered app.
     *
     * @param request httpServletRequest
     * @throws InvalidCredentialsException
     */
    private void handleErrorResponse(HttpServletRequest request) throws InvalidCredentialsException {
        if (request.getParameter(Office365AuthenticatorConstants.OAUTH2_PARAM_ERROR) != null) {
            StringBuilder errorMessage = new StringBuilder();
            String error = request.getParameter(Office365AuthenticatorConstants.OAUTH2_PARAM_ERROR);
            String errorDescription = request.getParameter
                    (Office365AuthenticatorConstants.OAUTH2_PARAM_ERROR_DESCRIPTION);
            String state = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
            errorMessage.append(Office365AuthenticatorConstants.ERROR).append(error)
                    .append(Office365AuthenticatorConstants.ERROR_DESCRIPTION).append(errorDescription)
                    .append(Office365AuthenticatorConstants.STATE).append(state);
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate via office365 when unauthorized the registered app. " +
                        errorMessage.toString());
            }
            throw new InvalidCredentialsException(errorMessage.toString());
        }
    }

    /**
     * Authenticator flow process
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and doing complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        if (StringUtils.isNotEmpty(request.getParameter(Office365AuthenticatorConstants.CODE)) || StringUtils
                .isNotEmpty(request.getParameter(Office365AuthenticatorConstants.OAUTH2_PARAM_ERROR))) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            initiateAuthenticationRequest(request, response, context);
        }
        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String redirectUri = getCallbackUrl(authenticatorProperties);
        String loginPage = getAuthorizationServerEndpoint(context.getAuthenticatorProperties());
        String identifierParam = OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE + EQUAL + context.getContextIdentifier()
                + "," + Office365AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
        String queryParams = resolveDynamicParameter(context, request.getParameterMap());
        //resolves dynamic query parameters from "Additional Query Parameters"

        if (StringUtils.isNotEmpty(queryParams)) {
            queryParams = queryParams + QUERY_PARAM_SEPARATOR + identifierParam;
        } else {
            queryParams = identifierParam;
        }

        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + "?" + queryParams + QUERY_PARAM_SEPARATOR +
                    Office365AuthenticatorConstants.CLIENT_ID + EQUAL + clientId + QUERY_PARAM_SEPARATOR +
                    Office365AuthenticatorConstants.RESPONSE_TYPE + EQUAL +
                    OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE + QUERY_PARAM_SEPARATOR +
                    Office365AuthenticatorConstants.REDIRECT_URI + EQUAL + redirectUri + QUERY_PARAM_SEPARATOR +
                    Office365AuthenticatorConstants.Resource + EQUAL +
                    Office365AuthenticatorConstants.OFFICE365_RESOURCE));
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while redirecting", e);
        }
    }

    /**
     * Process the response of the office365 end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            handleErrorResponse(request);
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
            String json = sendRequest(Office365AuthenticatorConstants.office365_USERINFO_ENDPOINT,
                    oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN));
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
        } catch (OAuthProblemException | IOException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    /**
     * Get the oauth response
     *
     * @param oAuthClient   OAuthClient
     * @param accessRequest Access request to get accessToken
     * @return Response OAuthClientResponse.
     * @throws AuthenticationFailedException
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
     * Get the access request
     *
     * @param tokenEndPoint Office365 authorize endpoint URL.
     * @param clientId      The client ID of the client application that is registered in Azure AD.
     * @param code          Authorization code to be used to obtain the access token.
     * @param clientSecret  The value of the key that contains the client password.
     * @param callbackUrl   Specifies the reply URL of the application.
     * @return Response OAuthClientRequest.
     * @throws AuthenticationFailedException
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
     * Request user claims from user info endpoint.
     *
     * @param url         User info endpoint.
     * @param accessToken Access token.
     * @return Response string.
     * @throws IOException
     */
    @Override
    protected String sendRequest(String url, String accessToken) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Claim URL: " + url);
        }
        if (url == null) {
            return StringUtils.EMPTY;
        }
        URL obj = new URL(url);
        HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
        urlConnection.setRequestMethod(Office365AuthenticatorConstants.HTTP_GET);
        urlConnection.setRequestProperty(Office365AuthenticatorConstants.HEADER_ACCEPT,
                Office365AuthenticatorConstants.ODATA_ACCEPT_HEADER);
        urlConnection.setRequestProperty(Office365AuthenticatorConstants.Authorization,
                Office365AuthenticatorConstants.BEARER + accessToken);
        BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
        StringBuilder builder = new StringBuilder();
        String inputLine = reader.readLine();
        while (inputLine != null) {
            builder.append(inputLine).append("\n");
            inputLine = reader.readLine();
        }
        reader.close();

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            log.debug("response: " + builder.toString());
        }
        return builder.toString();
    }


    /**
     * Resolves dynamic query parameters from "Additional Query Parameters" string.
     *
     * @param context      authentication context
     * @param parameterMap request parameter map
     * @return resolved query parameters
     * @throws AuthenticationFailedException if an error occurs while resolving dynamic parameters
     */
    private String resolveDynamicParameter(AuthenticationContext context, Map<String, String[]> parameterMap)
            throws AuthenticationFailedException {

        String queryParameters =
                context.getAuthenticatorProperties().get(Office365AuthenticatorConstants.ADDITIONAL_QUERY_PARAMS);
        if (StringUtils.isNotBlank(queryParameters)) {
            String resolvedQueryParams = getResolvedQueryParams(queryParameters, parameterMap);
            context.getAuthenticatorProperties()
                    .put(Office365AuthenticatorConstants.ADDITIONAL_QUERY_PARAMS, resolvedQueryParams);
            return resolvedQueryParams;
        }
        return StringUtils.EMPTY;
    }

    /**
     * Checks for any dynamic query parameters and replaces it with the values in the request.
     *
     * @param queryParamString The query parameter string.
     * @param parameters       The parameter map of the request.
     * @return The query parameter string with the dynamic parameters replaced with the actual values.
     * @throws AuthenticationFailedException if an error occurs while resolving dynamic parameters.
     */
    private String getResolvedQueryParams(String queryParamString, Map<String, String[]> parameters)
            throws AuthenticationFailedException {

        if (StringUtils.isBlank(queryParamString)) {
            return StringUtils.EMPTY;
        }
        Matcher matcher = pattern.matcher(queryParamString);
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = getParameterFromParamMap(parameters, name);
            if (StringUtils.isBlank(value)) {
                String multiOptionURI = getParameterFromParamMap(parameters, MULTI_OPTION_URI);
                value = getParameterFromURIString(multiOptionURI, name);
            }
            if (log.isDebugEnabled()) {
                log.debug("InterpretQueryString name: " + name + ", value: " + value);
            }
            queryParamString = queryParamString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
        }
        if (log.isDebugEnabled()) {
            log.debug("Output QueryString: " + queryParamString);
        }
        return queryParamString;
    }

    /**
     * Gets the value of the parameter corresponding to the given parameter
     * name from the request's parameter map.
     *
     * @param parameters    The parameter map of the request.
     * @param parameterName The name of the parameter to be retrieved.
     * @return The value of the parameter if it is present in the parameter map.
     * If it is not present, an empty String is returned instead.
     */
    private String getParameterFromParamMap(Map<String, String[]> parameters, String parameterName) {

        String[] parameterValueMap = parameters.get(parameterName);
        if (parameterValueMap != null && parameterValueMap.length > 0) {
            return parameterValueMap[0];
        }
        return StringUtils.EMPTY;
    }

    /**
     * Parses the given URI String to get the parameter value corresponding to the
     * given parameter name.
     *
     * @param uriString     The URI String to be parsed.
     * @param parameterName The name of the parameter to be retrieved.
     * @return The value of the parameter if it is present in the URI String.
     * @throws AuthenticationFailedException if an error occurs while decoding the parameter value.
     * If it is not present, an empty String is returned instead.
     */
    private String getParameterFromURIString(String uriString, String parameterName)
            throws AuthenticationFailedException {

        if (StringUtils.isNotBlank(uriString)) {
            String[] queryParams = uriString.split(QUERY_PARAM_SEPARATOR, -1);
            for (String queryParam : queryParams) {
                String[] queryParamComponents = queryParam.split(EQUAL);
                if (queryParamComponents.length == 2 && queryParamComponents[0].equalsIgnoreCase(parameterName)) {
                    try {
                        return URLDecoder.decode(queryParamComponents[1], StandardCharsets.UTF_8.name());
                    } catch (UnsupportedEncodingException e) {
                        throw new AuthenticationFailedException("Error decoding parameter: " + e.getMessage());
                    }
                }
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * Retrieves the callback URL from the authenticator properties.
     * If not provided, falls back to the common authentication endpoint.
     *
     * @param authenticatorProperties the authenticator properties map.
     * @return the callback URL.
     * @throws IllegalStateException if the callback URL cannot be built.
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        String callbackUrl = authenticatorProperties.get(Office365AuthenticatorConstants.CALLBACK_URL);
        if (StringUtils.isNotEmpty(callbackUrl)) {
            return callbackUrl;
        }

        try {
            return ServiceURLBuilder.create()
                    .addPath(FrameworkConstants.COMMONAUTH)
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException urlBuilderException) {
            throw new RuntimeException("Error occurred while building the callback URL.", urlBuilderException);
        }
    }
}
