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

using System;
using System.Threading.Tasks;

namespace uniauth_net.oauth1a
{
    public class OAuth_v1a_WebServerFlow : OAuth_v1a_TwoLeggedFlow, IUserConsentHandler
    {
        protected string authorizeUrl = null; 
        
        public OAuth_v1a_WebServerFlow(string clientId, string clientSecret,
            string callbackUrl, string requestTokenUrl, string accessTokenUrl, string authorizeUrl)
            : base(clientId, clientSecret, callbackUrl, requestTokenUrl, accessTokenUrl)
        {
            this.authorizeUrl = authorizeUrl;
        }

        /// <summary>
        /// Takes user authorization viewer and invokes the OAuth pin/oob based webserver flow
        /// </summary>
        /// <return>The authorization url</return>        
        public virtual async Task<Uri> GetUserAuthorizationUrl()
        {
            //initialize the underlying OAuthorizer
            initOAuthorizer();

            base.OAuthState = OAuthState.REQUEST_TOKEN_WAIT;
            var token = await getRequestToken(requestTokenUrl);

            base.OAuthState = OAuthState.AUTH_TOKEN_WAIT;
            var authorizeUrlResponse = oauthorizer.BuildAuthorizeUrl(authorizeUrl, token);
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
            var result = await oauthorizer.GetAccessTokenAsync(accessTokenUrl, requestToken, verifier);

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
        public virtual async Task InvokeUserAuthorization(IUserAuthorizationViewer viewer)
        {
            //initialize the underlying OAuthorizer
            initOAuthorizer();

            base.OAuthState = OAuthState.REQUEST_TOKEN_WAIT;
            var token = await getRequestToken(requestTokenUrl);

            base.OAuthState = OAuthState.AUTH_TOKEN_WAIT;
            var authorizeUrlResponse = oauthorizer.BuildAuthorizeUrl(authorizeUrl, token);            
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
            if (callbackUrl.Equals("oob"))
                return false;

            Uri callBackUrl = new Uri(callbackUrl);
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
            OAuthState = OAuthState.ACCESS_TOKEN_WAIT;
            try
            {
                var output = oauthorizer.GetAuthorizeTokenFromResponse(authorizedUrl);
                var result = await oauthorizer.GetAccessTokenAsync(accessTokenUrl, requestToken, output.Token.Secret);

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
    }
}

