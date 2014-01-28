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
using System.Collections.Generic;
using System.Threading.Tasks;

namespace uniauth_net.oauth2
{
    public class OAuth_v2_TwoLeggedUserCredentials : OAuth_v2_Base
    {
        private string clientSecret = null;

        public OAuth_v2_TwoLeggedUserCredentials(
            string clientId, string clientSecret,
            string redirectUrl, string scope, string authorizationUrl)
            : base(clientId, redirectUrl, scope, authorizationUrl)
        {

            this.clientSecret = clientSecret;
        }

        /// <summary>
        /// Takes user authorization viewer and invokes the OAuth2, 2-legged-user-credentials flow
        /// </summary>
        /// <param name="viewer">The authorization viewer</param>        
        public virtual async Task<bool> InvokeUserAuthorization()
        {
            //initialize the underlying OAuthorizer
            initOAuthorizer(clientSecret);

            base.OAuthState = OAuthState.INITIALIZED;
            var parameters = new List<KeyValuePair<string, string>>(capacity: 6)
                {
                    new KeyValuePair<string,string>(Constants.CLIENT_SECRET, this.clientSecret)
                };

            var accessTokenUrl = oauthorizer.BuildAuthorizeUrl(authorizationUrl, Constants.GRANT_TYPE_CLIENT_CREDENTIALS, parameters);
            Uri authUri = new Uri(accessTokenUrl);

            OAuthState = OAuthState.ACCESS_TOKEN_WAIT;
            try
            {
                var result = await oauthorizer.GetAccessTokenAsync(accessTokenUrl);

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
            catch(Exception ex)
            {
                OAuthState = OAuthState.FAILED;
                throw ex;
            }
        }
    }
}

