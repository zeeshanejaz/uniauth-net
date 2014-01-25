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

namespace AsyncOAuth.OAuth2
{
    internal static class OAuthUtility
    {
        public static IEnumerable<KeyValuePair<string, string>> BuildBasicParameters(string clientId, IEnumerable<KeyValuePair<string, string>> optionalParameters = null)
        {
            Precondition.NotNullOrEmpty(clientId, "clientId");

            var parameters = new List<KeyValuePair<string, string>>(capacity: 8)
            {
                new KeyValuePair<string,string>(Constants.CLIENT_ID, clientId),
            };

            if (optionalParameters == null) optionalParameters = Enumerable.Empty<KeyValuePair<string, string>>();
            parameters.AddRange(optionalParameters);

            return parameters;
        }
    }
}