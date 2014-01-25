/*******************************************************************************
* The MIT License (MIT)
*
* Copyright (c) 2014 APIMatic Inc.
* Adopted from AsyncOAuth Project https://github.com/neuecc/AsyncOAuth
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
using uniauth_net.oauth2;

namespace AsyncOAuth.OAuth2
{
    /// <summary>OAuth2.0 Authorization Client</summary>
    internal class OAuthAuthorizer
    {
        readonly string clientId;
        readonly string clientSecret;
        readonly string redirectUrl;
        readonly string scope;

        private OAuthAuthorizer(string clientId, string clientSecret)
        {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.scope = string.Empty;
            this.redirectUrl = Constants.LOCALHOST;
        }
                
        public OAuthAuthorizer(string consumerKey, string consumerSecret, string redirectUrl, string scope)
            : this(consumerKey, consumerSecret)
        {
            this.redirectUrl = redirectUrl;
            this.scope = scope;
        }

        public OAuthAuthorizer(string consumerKey, string redirectUrl, string scope)            
        {
            this.clientId = consumerKey;
            this.clientSecret = null;
            this.redirectUrl = redirectUrl;
            this.scope = scope;
        }

        public TokenResponse<AccessToken> GetAccessTokenFromResponse(Uri url)
        {
            var tokenResponse = GetTokenResponseFromFragment<AccessToken>
                (url, Constants.ACCESS_TOKEN, (code, data) => new AccessToken(code, data));
            return tokenResponse;
        }

        public TokenResponse<AuthToken> GetAuthTokenFromResponse(Uri url)
        {
            var tokenResponse = GetTokenResponseFromQuery<AuthToken>
                (url, Constants.RESPONSE_TYPE_CODE, (code, data) => new AuthToken(code, data));
            return tokenResponse;
        }

        private TokenResponse<T> GetTokenResponseFromFragment<T> (
            Uri url, string tokenName, Func<string, ILookup<string, string>, T> tokenFactory) 
            where T : Token
        {
            var tokenBase = url.Fragment;
            if (tokenBase.StartsWith("#"))
                tokenBase = tokenBase.Substring(1);

            return extractTokenAndExtraData<T>(tokenName, tokenFactory, tokenBase);
        }

        private TokenResponse<T> GetTokenResponseFromQuery<T>(
            Uri url, string tokenName, Func<string, ILookup<string, string>, T> tokenFactory)
            where T : Token
        {
            var tokenBase = url.Query;
            if (tokenBase.StartsWith("?"))
                tokenBase = tokenBase.Substring(1);

            return extractTokenAndExtraData<T>(tokenName, tokenFactory, tokenBase);
        }

        private static TokenResponse<T> extractTokenAndExtraDataJson<T>(string tokenName,
            Func<string, ILookup<string, string>, T> tokenFactory, string tokenBase) where T : Token
        {
            var splitted = tokenBase.Replace(" : ",":").Replace("\"", "")
                .Split(new char[] {'{', '}', ' ', '\r', '\n', '\t'}, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Split(':')).ToLookup(xs => xs[0], xs => xs[1]);

            var code = splitted[tokenName].First().UrlDecode();
                       
            var extraData = splitted.Where(kvp => kvp.Key != tokenName)
                .SelectMany(g => g, (g, value) => new { g.Key, Value = value })
                .ToLookup(kvp => kvp.Key, kvp => kvp.Value);
            var token = tokenFactory(code, extraData);

            return new TokenResponse<T>(token);
        }

        private static TokenResponse<T> extractTokenAndExtraData<T>(string tokenName, 
            Func<string, ILookup<string, string>, T> tokenFactory, string tokenBase) where T : Token
        {
            var splitted = tokenBase.Split('&').Select(s => s.Split('=')).ToLookup(xs => xs[0], xs => xs[1]);
            var code = splitted[tokenName].First().UrlDecode();
                        
            var extraData = splitted.Where(kvp => kvp.Key != tokenName)
                .SelectMany(g => g, (g, value) => new { g.Key, Value = value })
                .ToLookup(kvp => kvp.Key, kvp => kvp.Value);
            var token = tokenFactory(code, extraData);

            return new TokenResponse<T>(token);
        }

        /// <summary>
        /// Build Authorization Url
        /// </summary>
        public string BuildAuthorizeUrl(string authUrl, 
            string responseType, IEnumerable<KeyValuePair<string, string>> optionalParameters = null)
        {
            Precondition.NotNull(authUrl, "authUrl");

            var parameters = new List<KeyValuePair<string, string>>(capacity: 8)
            {
                new KeyValuePair<string,string>(Constants.RESPONSE_TYPE, responseType),
                new KeyValuePair<string,string>(Constants.CLIENT_ID, clientId),
                new KeyValuePair<string,string>(Constants.REDIRECT_URI, redirectUrl),
                new KeyValuePair<string,string>(Constants.SCOPE, scope),
            };

            if (optionalParameters == null) optionalParameters = Enumerable.Empty<KeyValuePair<string, string>>();

            string stringParameter = optionalParameters
                .Where(x => x.Key.ToLower() != Constants.REALM)
                .Concat(parameters)
                .Select(p => new { Key = p.Key.UrlEncode(), Value = p.Value.UrlEncode() })
                .OrderBy(p => p.Key, StringComparer.Ordinal)
                .ThenBy(p => p.Value, StringComparer.Ordinal)
                .Select(p => p.Key + "=" + p.Value)
                .ToString("&");

            return string.Format("{0}?{1}", authUrl, stringParameter);
        }

        private async Task<TokenResponse<T>> GetTokenResponseAsync<T>(string url, OAuthMessageHandler handler,
            HttpContent postValue, Func<string, ILookup<string, string>, T> tokenFactory) where T : Token
        {
            var client = new HttpClient(handler);

            var response = await client.PostAsync(url, 
                postValue ?? new FormUrlEncodedContent(Enumerable.Empty<KeyValuePair<string, string>>()));

            var tokenBase = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                throw new HttpRequestException(response.StatusCode + ":" + tokenBase); // error message
            }
            
            if (tokenBase.Contains(Constants.ACCESS_TOKEN))
            {
                if (tokenBase.IsJson())
                    return extractTokenAndExtraDataJson(Constants.ACCESS_TOKEN, tokenFactory, tokenBase);
                else
                    return extractTokenAndExtraData(Constants.ACCESS_TOKEN, tokenFactory, tokenBase);
            }

            return null;
        }

        /// <summary>asynchronus get GetAccessToken</summary>
        public async Task<TokenResponse<AccessToken>> GetAccessTokenAsync(string accessTokenUrl, 
            IEnumerable<KeyValuePair<string, string>> parameters = null, HttpContent postValue = null)
        {
            Precondition.NotNull(accessTokenUrl, "accessTokenUrl");

            if (parameters == null) parameters = Enumerable.Empty<KeyValuePair<string, string>>();
            var handler = new OAuthMessageHandler(clientId, redirectUrl, optionalParameters: parameters);

            return await GetTokenResponseAsync(accessTokenUrl, handler, postValue, tokenFactory: (code, data) => new AccessToken(code, data));
        }
        
        /// <summary>asynchronus get GetAccessToken</summary>
        public async Task<TokenResponse<AccessToken>> GetAccessTokenAsync(string accessTokenUrl, AuthToken authToken, 
            string grantType, IEnumerable<KeyValuePair<string, string>> parameters = null, HttpContent postValue = null)
        {
            Precondition.NotNull(accessTokenUrl, "accessTokenUrl");
            Precondition.NotNull(authToken, "authToken");
            Precondition.NotNull(grantType, "grantType");
            Precondition.NotNull(clientId, "clientId");
            Precondition.NotNull(clientSecret, "clientSecret");

            var sendParameters = new List<KeyValuePair<string, string>>(capacity: 8)
                {
                    new KeyValuePair<string,string>(Constants.CODE, authToken.Code),
                    new KeyValuePair<string,string>(Constants.CLIENT_SECRET, clientSecret),                    
                    new KeyValuePair<string,string>(Constants.REDIRECT_URI, redirectUrl),
                    new KeyValuePair<string, string>(Constants.GRANT_TYPE, grantType)
                };

            if (parameters == null) parameters = Enumerable.Empty<KeyValuePair<string, string>>();
            var handler = new OAuthMessageHandler(clientId, redirectUrl, optionalParameters: parameters.Concat(sendParameters));
            
            return await GetTokenResponseAsync(accessTokenUrl, handler, postValue, (code, data) => new AccessToken(code, data));
        }
    }
}