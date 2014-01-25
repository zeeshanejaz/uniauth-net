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

namespace AsyncOAuth.OAuth2
{
    internal class Constants
    {
        public const string LOCALHOST = "http://localhost";        
        public const string RESPONSE_TYPE = "response_type";
        public const string RESPONSE_TYPE_CODE = "code";
        public const string RESPONSE_TYPE_token = "token";
        public const string REDIRECT_URI = "redirect_uri";
        public const string CLIENT_ID = "client_id";
        public const string CLIENT_SECRET = "client_secret";
        public const string ACCESS_TOKEN = "access_token";
        public const string SCOPE = "scope";
        public const string GRANT_TYPE = "grant_type";
        public const string GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";        
        public const string GRANT_TYPE_PASSWORD = "password";
        public const string GRANT_TYPE_AUTH_CODE = "authorization_code";
        public const string GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
        public const string USERNAME = "username";
        public const string PASSWORD = "password";
        public const string REALM = "realm";
        public const string CODE = "code";
        public const string EXPIRES_IN = "expires_in";
        public const string REFRESH_TOKEN = "refresh_token";
    }
}
