/*******************************************************************************
* The MIT License (MIT)
*
* Copyright (c) 2014 Yoshifumi Kawai (https://github.com/neuecc)
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
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using uniauth_net;
using uniauth_net.oauth1a;

namespace AsyncOAuth.OAuth1a
{
    /// <summary>OAuth Authorization Client</summary>
    internal class OAuthAuthorizer
    {
        readonly string consumerKey;
        readonly string consumerSecret;
        readonly string callBackUrl;

        public OAuthAuthorizer(string consumerKey, string consumerSecret)
        {
            this.consumerKey = consumerKey;
            this.consumerSecret = consumerSecret;
        }

        public OAuthAuthorizer(string consumerKey, string consumerSecret, string callBackUrl)
            :this(consumerKey, consumerSecret)
        {
            this.callBackUrl = callBackUrl;
        }

        public TokenResponse<RequestToken> GetAuthorizeTokenFromResponse(Uri url)
        {
            var tokenResponse = GetAuthorizeTokenResponse<RequestToken>
                (url, (key, secret, data) => new RequestToken(key, secret, data));
            return tokenResponse;
        }

        TokenResponse<T> GetAuthorizeTokenResponse<T>
            (Uri url, Func<string, string, ILookup<string, string>, T> tokenFactory) where T : BaseToken
        {
            var tokenBase = url.Query;
            if (tokenBase.StartsWith("?"))
                tokenBase = tokenBase.Substring(1);

            return extractTokenAndExtraData<T>(tokenFactory, tokenBase);
        }

        private static TokenResponse<T> extractTokenAndExtraData<T>
            (Func<string, string, ILookup<string, string>, T> tokenFactory, string tokenBase) where T : BaseToken
        {
            var splitted = tokenBase.Split('&').Select(s => s.Split('=')).ToLookup(xs => xs[0], xs => xs[1]);
            var key = splitted[Constants.OAUTH_TOKEN].First().UrlDecode();
            var secret = splitted.Contains(Constants.OAUTH_TOKEN_SECRET) ?
                splitted[Constants.OAUTH_TOKEN_SECRET].First().UrlDecode() :
                splitted[Constants.OAUTH_VERIFIER].First().UrlDecode();
                        
            var extraData = splitted
                .Where(kvp  => (kvp.Key != Constants.OAUTH_TOKEN)
                            && (kvp.Key != Constants.OAUTH_TOKEN_SECRET)
                            && (kvp.Key != Constants.OAUTH_VERIFIER))
                .SelectMany(g => g, (g, value) => new { g.Key, Value = value })
                .ToLookup(kvp => kvp.Key, kvp => kvp.Value);
            var token = tokenFactory(key, secret, extraData);

            return new TokenResponse<T>(token);
        }

        private async Task<TokenResponse<T>> getTokenResponseAsync<T>(string url, OAuthMessageHandler handler,
            HttpContent postValue, Func<string, string, ILookup<string, string>, T> tokenFactory) where T : BaseToken
        {
            var client = new HttpClient(handler);

            var response = await client.PostAsync(url, postValue ?? new FormUrlEncodedContent(Enumerable.Empty<KeyValuePair<string, string>>()));
            var tokenBase = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                throw new HttpRequestException(response.StatusCode + ":" + tokenBase); // error message
            }

            return extractTokenAndExtraData<T>(tokenFactory, tokenBase);
        }

        /// <summary>
        /// Given the request token, this method prepares the resource authorization url, which
        /// may be opened in a WebView for user login and consent. Some providers force show the
        /// consent page even if the consent was previously granted (e.g., Vimeo), while others
        /// do not exhibit this behaviour. It is therefore advised to not hide the WebView when 
        /// authorization url is loaded.
        /// </summary>
        /// <param name="authUrl">The authorization url to prepare with request</param>
        /// <param name="requestToken">The request token to use for preparing authorization request</param>
        /// <returns>Url of the resource authorization page</returns>
        public string BuildAuthorizeUrl(string authUrl, RequestToken requestToken)
        {
            Precondition.NotNull(authUrl, "authUrl");
            Precondition.NotNull(requestToken, "accessToken");

            return string.Format("{0}?{1}={2}", authUrl, Constants.OAUTH_TOKEN, requestToken.Key);
        }

        /// <summary>
        /// Gets the request token from the request token url.
        /// </summary>
        /// <param name="requestTokenUrl">The request token url</param>
        /// <param name="parameters">Any additional query parameters that may be required</param>
        /// <param name="postValue">Any additional fields that may be required</param>
        /// <returns>Token response containing request token, if successful</returns>
        public async Task<TokenResponse<RequestToken>> GetRequestTokenAsync(string requestTokenUrl,
            IEnumerable<KeyValuePair<string, string>> parameters = null, HttpContent postValue = null)
        {
            Precondition.NotNull(requestTokenUrl, "requestTokenUrl");

            var handler = new OAuthMessageHandler(consumerKey, consumerSecret, callBackUrl, token: null, optionalOAuthHeaderParameters: parameters);
            return await getTokenResponseAsync(requestTokenUrl, handler, postValue, (key, secret, data) => new RequestToken(key, secret, data));
        }

        /// <summary>
        /// Gets the access token using the request token. This is useful for 2-legged flows
        /// where verification is not required.
        /// </summary>
        /// <remarks>Zeeshan Bhatti</remarks>
        /// <param name="accessTokenUrl">The url for the access token</param>
        /// <param name="requestToken">The request token to trade for access token</param>
        /// <param name="parameters">Any additional query parameters that may be required</param>
        /// <param name="postValue">Any additional fields that may be required</param>
        /// <returns>Token response containing access token, if successful</returns>
        public async Task<TokenResponse<AccessToken>> GetAccessTokenAsync(string accessTokenUrl, 
            RequestToken requestToken, IEnumerable<KeyValuePair<string, string>> parameters = null, HttpContent postValue = null)
        {
            Precondition.NotNull(accessTokenUrl, "accessTokenUrl");
            Precondition.NotNull(requestToken, "requestToken");
                        
            if (parameters == null) parameters = Enumerable.Empty<KeyValuePair<string, string>>();
            var handler = new OAuthMessageHandler(consumerKey, consumerSecret, callBackUrl, 
                token: requestToken, optionalOAuthHeaderParameters: parameters);

            return await getTokenResponseAsync(accessTokenUrl, handler, postValue, (key, secret, data) => new AccessToken(key, secret, data));
        }

        /// <summary>
        /// Gets the access token using the request token. This is useful for 3-legged flows
        /// (browser-based abd webserver based) where verification is required.
        /// </summary>
        /// <remarks>Zeeshan Bhatti</remarks>
        /// <param name="accessTokenUrl">The url for the access token</param>
        /// <param name="requestToken">The request token to trade for access token</param>
        /// <param name="verifier">The verification code generated by the resource authorization</param>
        /// <param name="parameters">Any additional query parameters that may be required</param>
        /// <param name="postValue">Any additional fields that may be required</param>
        /// <returns>Token response containing access token, if successful</returns>
        public async Task<TokenResponse<AccessToken>> GetAccessTokenAsync(string accessTokenUrl,
            RequestToken requestToken, string verifier, IEnumerable<KeyValuePair<string, string>> parameters = null, HttpContent postValue = null)
        {
            Precondition.NotNull(verifier, "verifier");

            var verifierParam = new KeyValuePair<string, string>(Constants.OAUTH_VERIFIER, verifier.Trim());

            if (parameters == null) parameters = Enumerable.Empty<KeyValuePair<string, string>>();
            var handler = new OAuthMessageHandler(consumerKey, consumerSecret, callBackUrl,
                token: requestToken, optionalOAuthHeaderParameters: parameters.Concat(new[] { verifierParam }));

            return await getTokenResponseAsync(accessTokenUrl, handler, postValue, (key, secret, data) => new AccessToken(key, secret, data));
        }
    }
}