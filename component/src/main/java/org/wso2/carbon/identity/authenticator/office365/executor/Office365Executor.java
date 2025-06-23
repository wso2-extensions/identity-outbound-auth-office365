/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.authenticator.office365.executor;

import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.authenticator.office365.Office365AuthenticatorConstants;

import java.util.Map;

/**
 * Office 365 OpenID Connect executor.
 * This class is used to handle the OpenID Connect specific operations for Office 365 authenticator.
 */
public class Office365Executor extends OpenIDConnectExecutor {

    public static final String EXECUTOR_NAME = "Office365Executor";

    @Override
    public String getName() {

        return EXECUTOR_NAME;
    }

    @Override
    public String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        String authzEndpoint = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        if (authzEndpoint == null) {
            authzEndpoint = Office365AuthenticatorConstants.office365_OAUTH_ENDPOINT;
        }
        return authzEndpoint;
    }

    @Override
    public String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenEndpoint = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        if (tokenEndpoint == null) {
            tokenEndpoint = Office365AuthenticatorConstants.office365_TOKEN_ENDPOINT;
        }
        return tokenEndpoint;
    }

    @Override
    public String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        String userInfoEndpoint =
                authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
        if (userInfoEndpoint == null) {
            userInfoEndpoint = Office365AuthenticatorConstants.office365_USERINFO_ENDPOINT;
        }
        return userInfoEndpoint;
    }

    @Override
    public String getAuthenticatedUserIdentifier(Map<String, Object> jsonObject) {

        Object emailClaim = jsonObject.get(OIDCAuthenticatorConstants.Claim.EMAIL);
        if (emailClaim == null) {
            return (String) jsonObject.get(OIDCAuthenticatorConstants.Claim.SUB);
        } else {
            return (String) emailClaim;
        }
    }
}
