/*******************************************************************************
* The MIT License (MIT)
*
* Copyright (c) 2014 Zeeshan Ejaz Bhatti
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

using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace AsyncOAuth.OAuth2
{
    // idea is based on http://blogs.msdn.com/b/henrikn/archive/2012/02/16/extending-httpclient-with-oauth-to-access-twitter.aspx
    internal class OAuthMessageHandler : DelegatingHandler
    {
        private string clientId;
        private string redirectUrl;
        private IEnumerable<KeyValuePair<string, string>> parameters;

        public OAuthMessageHandler(string clientId, string redirectUrl, IEnumerable<KeyValuePair<string, string>> optionalParameters = null)            
            :base(new HttpClientHandler())
        {
            this.clientId = clientId;
            this.redirectUrl = (redirectUrl == null) ? Constants.LOCALHOST : redirectUrl;
            this.parameters = optionalParameters ?? Enumerable.Empty<KeyValuePair<string, string>>();
        }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            var sendParameter = parameters;
            if (request.Method == HttpMethod.Post)
            {
                // form url encoded content
                if (request.Content is FormUrlEncodedContent)
                {
                    // url encoded string
                    var extraParameter = await request.Content.ReadAsStringAsync();
                    var parsed = Utility.ParseQueryString(extraParameter); // url decoded
                    sendParameter = sendParameter.Concat(parsed);
                }
            }

            var authParams = OAuthUtility.BuildBasicParameters(clientId, sendParameter);
            
            if (request.Method == HttpMethod.Post)
            {
                request.Content = new FormUrlEncodedContent(authParams);
            }
            else if (request.Method == HttpMethod.Get)
            {
                var queryData = authParams.Select(p => p.Key + "=" + p.Value).ToString("&");
                string  newQuery = request.RequestUri.Query;

                if (string.IsNullOrWhiteSpace(newQuery))
                    newQuery = "?" + queryData;
                else
                    newQuery += "&" + queryData;

                request.RequestUri = new System.Uri(request.RequestUri.OriginalString + newQuery);
            }

            return base.SendAsync(request, cancellationToken).Result;
        }
    }
}