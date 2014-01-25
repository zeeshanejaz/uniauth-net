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

using AsyncOAuth.OAuth1a;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;

namespace uniauth_net.oauth1a
{
    public abstract class OAuth_v1a_Base : IAuthProvider
    {
        internal OAuthAuthorizer oauthorizer = null;
        protected RequestToken requestToken = null;
        public AccessToken AccessToken { get; internal set; }

        protected string clientId = null;
        protected string clientSecret = null;
        protected string callbackUrl = null;

        public void RestoreAccessToken(string accessToken, string tokenSecret)
        {
            this.AccessToken = new AccessToken(accessToken, tokenSecret, null);
        }

        protected OAuth_v1a_Base(string clientId, string clientSecret, string callbackUrl)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.callbackUrl = callbackUrl;
            OAuthState = OAuthState.INITIALIZED;
        }
        
        //lazy initialization of oauthorizer
        protected void initOAuthorizer()
        {
            oauthorizer = new OAuthAuthorizer(clientId, clientSecret, callbackUrl);
        }

        /// <summary>
        /// The current state of OAuth process
        /// </summary>
        public OAuthState OAuthState { get; protected set; }

        /// <summary>
        /// Get the request token from the request token url and store for using later.
        /// </summary>
        /// <returns>request token</returns>
        protected async Task<RequestToken> getRequestToken(string requestTokenUrl)
        {
            try
            {
                var requestTokenResponse = await oauthorizer.GetRequestTokenAsync(requestTokenUrl);
                if ((requestTokenResponse == null) || (requestTokenResponse.Token == null))
                    throw new InvalidOperationException("Unable to get request token.");

                requestToken = requestTokenResponse.Token;
                return requestToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

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

            IEnumerable<KeyValuePair<string, string>> sendParameter = Enumerable.Empty<KeyValuePair<string, string>>();

            var headerParams = OAuthUtility.BuildBasicParameters(
                    clientId, clientSecret, callbackUrl, request.RequestUri.OriginalString,
                    request.Method, AccessToken, sendParameter);

            foreach (var pair in headerParams)
            {
                request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }

            IEnumerable<string> keyValPairs = headerParams.Select(p => string.Format("{0}=\"{1}\"", p.Key, p.Value));
            var authHeaderVal = string.Join(",", keyValPairs);

            request.Headers.Add("Authorization", string.Format("OAuth {0}", authHeaderVal));
            return true;
        }
    }
}

