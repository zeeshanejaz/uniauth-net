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
using System;
using System.Net.Http;
using System.Text;

namespace uniauth_net.basic
{
    public class BasicAuthHandler : IAuthProvider
    {
        private string username = null;
        private string password = null;

        public BasicAuthHandler(string username, string password)
        {
            this.username = username;
            this.password = password;
        }

        public bool AppendCredentials(HttpRequestMessage request)
        {
            Precondition.NotNull(username, "username");
            Precondition.NotNull(password, "password");

            string accessToken = Convert.ToBase64String(
                        UTF8Encoding.UTF8.GetBytes(string.Format("{0}:{1}",
                            this.username, this.password))
                        );

            string authValue = string.Format("Basic {0}", accessToken);
            request.Headers.Add("Authorization", authValue);
            return true;
        }
    }
}
