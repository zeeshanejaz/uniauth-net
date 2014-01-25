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

namespace AsyncOAuth.OAuth1a
{
    internal class Constants
    {
        public const string OAUTH_TOKEN = "oauth_token";
        public const string OAUTH_TOKEN_SECRET = "oauth_token_secret";
        public const string OAUTH_VERIFIER = "oauth_verifier";
        public const string LOCALHOST = "http://localhost";
        public const string OAUTH_HEADER_TYPE = "OAuth";

        public const string OAUTH_CONSUMER_KEY = "oauth_consumer_key";
        public const string OAUTH_CALLBACK = "oauth_callback";
        public const string OAUTH_NONCE = "oauth_nonce";
        public const string OAUTH_TIMESTAMP = "oauth_timestamp";
        public const string OAUTH_SIGNATURE = "oauth_signature";
        public const string OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
        public const string OAUTH_VERSION = "oauth_version";
        public const string HMAC_SHA1 = "HMAC-SHA1";
    }
}
