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
    public class OAuth_v2_PinBasedFlow : OAuth_v2_ThreeLeggedBase
    {
        public OAuth_v2_PinBasedFlow(string clientId, string clientSecret,
            string redirectUrl, string scope, string authorizationUrl, string accessTokenUrl)
            : base(clientId, clientSecret, redirectUrl, scope, authorizationUrl, accessTokenUrl)
        {
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
            var authorizeUrlResponse = oauthorizer.BuildAuthorizeUrl(authorizationUrl, Constants.RESPONSE_TYPE_CODE);
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
            var result = await oauthorizer.GetAccessTokenAsync(accessTokenUrl, authToken, Constants.GRANT_TYPE_AUTH_CODE);
            
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
    }
}

