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

/*
 * Define all constants used for Office365 Authenticator.
 */
public class Office365AuthenticatorConstants {
    //Authenticator name
    public static final String AUTHENTICATOR_NAME = "Office365Authenticator";
    //Authenticator friendly name
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Office365";
    //office365 authorize endpoint URL
    public static final String office365_OAUTH_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/authorize";
    //office365 token  endpoint URL
    public static final String office365_TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/token";
    //office365 user info endpoint URL
    public static final String office365_USERINFO_ENDPOINT = "https://outlook.office365.com/api/v2.0/me";
    public static final String Resource = "resource";
    // The client ID of the client application that is registered in Azure AD.
    public static final String CLIENT_ID = "client_id";
    //The reply URL of the application.
    public static final String CALLBACK_URL = "callbackUrl";
    //The ID of the user
    public static final String ID = "Id";
    //The authorization code that the application requested.
    public static final String CODE = "code";
    //The response type
    public static final String RESPONSE_TYPE = "response_type";
    //Specifies the reply URL of the application.
    public static final String REDIRECT_URI = "redirect_uri";
    //The App ID URI of the web API
    public static final String OFFICE365_RESOURCE = "https://outlook.office.com";
    //The Http get method
    public static final String HTTP_GET = "GET";
    //The Accept header
    public static final String HEADER_ACCEPT = "ACCEPT";
    //The value of the Accept header
    public static final String ODATA_ACCEPT_HEADER = "application/json;odata.metadata=minimal";
    //The Authorization header
    public static final String Authorization = "Authorization";
    //The Bearer type
    public static final String BEARER = "Bearer ";
    //A randomly generated non-reused value that is sent in the request and returned in the response.
    public static final String STATE = "state";
}