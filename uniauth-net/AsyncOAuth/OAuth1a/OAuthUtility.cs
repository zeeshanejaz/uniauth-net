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
using System.Security.Cryptography;
using System.Text;
using uniauth_net.oauth1a;

namespace AsyncOAuth.OAuth1a
{
    internal static class OAuthUtility
    {
        public delegate byte[] HashFunction(byte[] key, byte[] buffer);

        private static readonly Random random = new Random();

        /// <summary>
        /// <para>hashKey -> buffer -> hashedBytes</para>
        /// <para>ex:</para>
        /// <para>ComputeHash = (key, buffer) => { using (var hmac = new HMACSHA1(key)) { return hmac.ComputeHash(buffer); } };</para>
        /// <para>ex(WinRT): </para>
        /// <para>ComputeHash = (key, buffer) =></para>
        /// <para>{</para>
        /// <para>&#160;&#160;&#160;&#160;var crypt = Windows.Security.Cryptography.Core.MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");</para>
        /// <para>&#160;&#160;&#160;&#160;var keyBuffer = Windows.Security.Cryptography.CryptographicBuffer.CreateFromByteArray(key);</para>
        /// <para>&#160;&#160;&#160;&#160;var cryptKey = crypt.CreateKey(keyBuffer);</para>
        /// <para>&#160;</para>
        /// <para>&#160;&#160;&#160;&#160;var dataBuffer = Windows.Security.Cryptography.CryptographicBuffer.CreateFromByteArray(buffer);</para>
        /// <para>&#160;&#160;&#160;&#160;var signBuffer = Windows.Security.Cryptography.Core.CryptographicEngine.Sign(cryptKey, dataBuffer);</para>
        /// <para>&#160;</para>
        /// <para>&#160;&#160;&#160;&#160;byte[] value;</para>
        /// <para>&#160;&#160;&#160;&#160;Windows.Security.Cryptography.CryptographicBuffer.CopyToByteArray(signBuffer, out value);</para>
        /// <para>&#160;&#160;&#160;&#160;return value;</para>
        /// <para>};</para>
        /// </summary>
        public static HashFunction ComputeHash
        {
            get
            {
                return (key, buffer) => { using (var hmac = new HMACSHA1(key)) { return hmac.ComputeHash(buffer); } };
            }
        }

        static string GenerateSignature(string consumerSecret, Uri uri, HttpMethod method, Token token, IEnumerable<KeyValuePair<string, string>> parameters)
        {
            var hmacKeyBase = consumerSecret.UrlEncode() + "&" + ((token == null) ? "" : token.Secret).UrlEncode();

            // escaped => unescaped[]
            var queryParams = Utility.ParseQueryString(uri.GetComponents(UriComponents.Query | UriComponents.KeepDelimiter, UriFormat.UriEscaped));

            var stringParameter = parameters
                .Where(x => x.Key.ToLower() != "realm")
                .Concat(queryParams)
                .Select(p => new { Key = p.Key.UrlEncode(), Value = p.Value.UrlEncode() })
                .OrderBy(p => p.Key, StringComparer.Ordinal)
                .ThenBy(p => p.Value, StringComparer.Ordinal)
                .Select(p => p.Key + "=" + p.Value)
                .ToString("&");
            var signatureBase = method.ToString() +
                "&" + uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped).UrlEncode() +
                "&" + stringParameter.UrlEncode();

            var hash = ComputeHash(Encoding.UTF8.GetBytes(hmacKeyBase), Encoding.UTF8.GetBytes(signatureBase));
            return Convert.ToBase64String(hash).UrlEncode();
        }

        public static IEnumerable<KeyValuePair<string, string>> BuildBasicParameters(string consumerKey, string consumerSecret, string callBackUrl, string url, HttpMethod method, Token token = null, IEnumerable<KeyValuePair<string, string>> optionalParameters = null)
        {
            Precondition.NotNull(url, "url");

            var parameters = new List<KeyValuePair<string, string>>(capacity: 8)
            {
                new KeyValuePair<string,string>(Constants.OAUTH_CONSUMER_KEY, consumerKey),
                new KeyValuePair<string,string>(Constants.OAUTH_CALLBACK, callBackUrl),
                new KeyValuePair<string,string>(Constants.OAUTH_NONCE, random.Next().ToString() ),
                new KeyValuePair<string,string>(Constants.OAUTH_TIMESTAMP, DateTime.UtcNow.ToUnixTime().ToString() ),
                new KeyValuePair<string,string>(Constants.OAUTH_SIGNATURE_METHOD, Constants.HMAC_SHA1),
                new KeyValuePair<string,string>(Constants.OAUTH_VERSION, "1.0" )
            };
            if (token != null) parameters.Add(new KeyValuePair<string, string>(Constants.OAUTH_TOKEN, token.Key));
            if (optionalParameters == null) optionalParameters = Enumerable.Empty<KeyValuePair<string, string>>();

            var signature = GenerateSignature(consumerSecret, new Uri(url), method, token, parameters.Concat(optionalParameters));

            parameters.Add(new KeyValuePair<string, string>(Constants.OAUTH_SIGNATURE, signature));

            return parameters;
        }
    }
}