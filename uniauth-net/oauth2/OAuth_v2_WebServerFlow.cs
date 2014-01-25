/*******************************************************************************
* The MIT License (MIT)
*
* Copyright (c) 2014 Zeeshan Ejaz Bhatti
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
/******************************************************************************/

using AsyncOAuth.OAuth2;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace uniauth_net.oauth2
{
    public class OAuth_v2_WebServerFlow : OAuth_v2_Base, IUserConsentHandler
    {
        private string tokenUrl = null;
        private string clientSecret = null;

        public OAuth_v2_WebServerFlow(string clientId, string clientSecret,
            string redirectUrl, string scope, string authUrl, string tokenUrl)
            : base(clientId, redirectUrl, scope, authUrl)
        {
            this.tokenUrl = tokenUrl;
            this.clientSecret = clientSecret;
        }

        /// <summary>
        /// Takes user authorization viewer and invokes the OAuth pin/oob based webserver flow
        /// </summary>
        /// <return>The authorization url</return>        
        public virtual Uri GetUserTokenUrl()
        {
            //initialize the underlying OAuthorizer
            initOAuthorizer(clientSecret);

            base.OAuthState = OAuthState.AUTH_TOKEN_WAIT;
            var authorizeUrlResponse = oauthorizer.BuildAuthorizeUrl(authUrl, Constants.RESPONSE_TYPE_CODE);
            return new Uri(authorizeUrlResponse);
        }

        /// <summary>
        /// The resultant callback url to process as the result of authorization.
        /// </summary>
        /// <param name="authorizedUrl">The return url sent back with key and secret</param>
        /// <returns>True if the process of authorization was successful</returns>
        public async virtual Task<bool> ProcessUserAuthorizationAsync(string verifier)
        {
            OAuthState = OAuthState.ACCESS_TOKEN_WAIT;
            authToken = new AuthToken(verifier, null);
            var result = await oauthorizer.GetAccessTokenAsync(tokenUrl, authToken, Constants.GRANT_TYPE_AUTH_CODE);
            
            if (result != null)
            {
                OAuthState = OAuthState.SUCCEEDED;
                AccessToken = result.Token;
                return true;
            }
            else
            {
                OAuthState = OAuthState.FAILED;
                return false;
            }        
        }

        /// <summary>
        /// Takes user authorization viewer and invokes the OAuth webserver flow
        /// </summary>
        /// <param name="viewer">The authorization viewer</param>        
        public virtual void InvokeUserAuthorization(IUserAuthorizationViewer viewer)
        {
            //initialize the underlying OAuthorizer
            initOAuthorizer(clientSecret);
            
            base.OAuthState = OAuthState.AUTH_TOKEN_WAIT;
            var authorizeUrlResponse = oauthorizer.BuildAuthorizeUrl(authUrl, "code");
            viewer.AuthorizeUrl = new Uri(authorizeUrlResponse);
            viewer.AuthController = this;
        }

        /// <summary>
        /// Checks if the given url is callback url.
        /// This is used for checking if OAuth flow has completed. 
        /// </summary>
        /// <param name="currentUrl">The current url to check against callback</param>
        /// <returns>True if the given url is callback url</returns>
        public virtual bool IsCallBack(Uri currentUrl)
        {
            if (redirectUrl.Equals("oob"))
                return false;

            Uri callBackUrl = new Uri(redirectUrl);
            UriComponents components = (UriComponents.SchemeAndServer | UriComponents.Path);

            string value1 = currentUrl.GetComponents(components, UriFormat.Unescaped);
            string value2 = callBackUrl.GetComponents(components, UriFormat.Unescaped);
            return string.Equals(value1, value2, StringComparison.Ordinal);
        }

        /// <summary>
        /// The resultant callback url to process as the result of authorization.
        /// </summary>
        /// <param name="authorizedUrl">The return url sent back with key and secret</param>
        /// <returns>True if the process of authorization was successful</returns>
        public async virtual Task<bool> ProcessUserAuthorizationAsync(Uri authorizedUrl)
        {
            OAuthState = OAuthState.AUTH_TOKEN_WAIT;
            var output = oauthorizer.GetAuthTokenFromResponse(authorizedUrl);
            authToken = output.Token;
            
            OAuthState = OAuthState.ACCESS_TOKEN_WAIT;
            try
            {
                var result = await oauthorizer.GetAccessTokenAsync(tokenUrl, authToken, Constants.GRANT_TYPE_AUTH_CODE);

                if (result != null)
                {
                    OAuthState = OAuthState.SUCCEEDED;
                    AccessToken = result.Token;
                    return true;
                }
                else
                {
                    OAuthState = OAuthState.FAILED;
                    return false;
                }
            }
            catch (Exception ex)
            {
                OAuthState = OAuthState.FAILED;
                throw ex;
            }
        }
        
        public async Task<bool> RefreshAccessToken()
        {
            //initialize the underlying OAuthorizer
            if (oauthorizer == null)                
                initOAuthorizer(clientSecret);

            if (OAuthState != OAuthState.SUCCEEDED)
            {
                throw new InvalidOperationException("The request must be authorized before refresh.");
            }

            if (AccessToken == null)
            {
                throw new InvalidOperationException("The access token has not previously been acquired.");
            }

            if (string.IsNullOrWhiteSpace(AccessToken.RefreshToken))
            {
                throw new InvalidOperationException("Refresh token was not found.");
            }

            OAuthState = OAuthState.REFRESH_WAIT;

            var parameters = new List<KeyValuePair<string, string>>(capacity: 6)
                {
                    new KeyValuePair<string,string>(Constants.REFRESH_TOKEN, this.AccessToken.RefreshToken),
                    new KeyValuePair<string,string>(Constants.CLIENT_SECRET, this.clientSecret)
                };

            var accessTokenUrl = oauthorizer.BuildAuthorizeUrl(authUrl, Constants.GRANT_TYPE_REFRESH_TOKEN, parameters);
            Uri authUri = new Uri(accessTokenUrl);

            OAuthState = OAuthState.ACCESS_TOKEN_WAIT;
            try
            {
                var result = await oauthorizer.GetAccessTokenAsync(accessTokenUrl);

                if (result != null)
                {
                    OAuthState = OAuthState.SUCCEEDED;  
                    var token = result.Token;
                    base.RestoreAccessToken(token.Code, token.Expires, token.RefreshToken);

                    return true;
                }
                else
                {
                    OAuthState = OAuthState.FAILED;
                    return false;
                }
            }
            catch (Exception ex)
            {
                OAuthState = OAuthState.FAILED;
                throw ex;
            }
        }
    }
}

