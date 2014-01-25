/*******************************************************************************
* The MIT License (MIT)
*
* Copyright (c) 2014 APIMatic Inc.
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

using AsyncOAuth;
using AsyncOAuth.OAuth2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace uniauth_net.oauth2
{
    public abstract class OAuth_v2_Base : IAuthProvider
    {
        internal OAuthAuthorizer oauthorizer = null;
        protected AuthToken authToken = null;

        public AccessToken AccessToken { get; internal set; }

        protected string clientId = null;
        protected string redirectUrl = null;
        protected string authUrl = null;
        protected string scope = null;

        public void RestoreAccessToken(string accessToken, string expiresIn = null, string refreshToken = null)
        {
            var parameters = new List<KeyValuePair<string, string>>();
            
            if(!string.IsNullOrWhiteSpace(expiresIn))
                parameters.Add(new KeyValuePair<string, string>(Constants.EXPIRES_IN, expiresIn));

            if(!string.IsNullOrWhiteSpace(refreshToken))
                parameters.Add(new KeyValuePair<string, string>(Constants.REFRESH_TOKEN, refreshToken));

            this.AccessToken = new AccessToken(accessToken, parameters.ToLookup(kvp => kvp.Key, kvp => kvp.Value));
        }

        protected OAuth_v2_Base(string clientId, string redirectUrl, string scope, string authUrl)
        {
            this.clientId = clientId;         
            this.redirectUrl = redirectUrl;         
            this.scope = scope;
            this.authUrl = authUrl;
            OAuthState = OAuthState.INITIALIZED;
        }
        
        //lazy initialization of oauthorizer
        protected void initOAuthorizer()
        {
            oauthorizer = new OAuthAuthorizer(clientId, redirectUrl, scope);
        }

        //lazy initialization of oauthorizer
        protected void initOAuthorizer(string clientSecret)
        {
            oauthorizer = new OAuthAuthorizer(clientId, clientSecret, redirectUrl, scope);
        }

        /// <summary>
        /// The current state of OAuth process
        /// </summary>
        public OAuthState OAuthState { get; protected set; }
        
        /// <summary>
        /// Appends the necessary OAuth credentials for making this authorized call
        /// </summary>
        /// <param name="request">The out going request to access the resource</param>
        /// <returns>True</returns>
        public virtual bool AppendCredentials(HttpRequestMessage request)
        {
            if (OAuthState == OAuthState.FAILED)
            {
                throw new InvalidOperationException("The OAuth process has failed to authorize this request.");
            }
            else if (OAuthState != OAuthState.SUCCEEDED)
            {
                throw new InvalidOperationException("The OAuth process must finish before this request can be made.");
            }

            string headerVal = AccessToken.Code;
            request.Headers.TryAddWithoutValidation("Authorization", string.Format("Bearer {0}", headerVal));
            return true;
        }
    }
}

