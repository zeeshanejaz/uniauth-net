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

using AsyncOAuth;
using AsyncOAuth.OAuth2;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;

#pragma warning disable 612, 618

namespace uniauth_net.oauth2
{
    /// <summary>represents OAuth Token</summary>
    [DebuggerDisplay("Code = {Code}")]
    [DataContract]
    public abstract class Token : BaseToken
    {
        [DataMember(Order = 1)]
        public string Code { get; private set; }

        /// <summary>for serialize.</summary>
        [Obsolete("this is used for serialize")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Token()
        { }

        public Token(string code, ILookup<string, string> extraData)
        {
            Precondition.NotNull(code, "code");

            this.Code = code;
            base.ExtraData = extraData;
        }
    }

    /// <summary>represents OAuth2 AuthToken</summary>
    [DataContract]
    public class AuthToken : Token
    {
        /// <summary>for serialize.</summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public AuthToken()
        { }

        public AuthToken(string code, ILookup<string, string> extraData)
            : base(code, extraData)
        { }
    }

    /// <summary>represents OAuth2 AccessToken</summary>
    [DataContract]
    public class AccessToken : Token
    {
        /// <summary>for serialize.</summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public AccessToken()
        { }

        public AccessToken(string accessToken, ILookup<string, string> extraData)
            : base(accessToken, extraData)
        { }

        public string Expires
        {
            get
            {
                if (ExtraData == null)
                    return null;

                return ExtraData[Constants.EXPIRES_IN].FirstOrDefault();
            }
        }

        public string RefreshToken
        {
            get
            {
                if (ExtraData == null)
                    return null;

                return ExtraData[Constants.REFRESH_TOKEN].FirstOrDefault();
            }
        }
    }
}

#pragma warning restore 612, 618