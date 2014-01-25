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
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;

#pragma warning disable 612, 618

namespace uniauth_net.oauth1a
{
    /// <summary>represents OAuth Token</summary>
    [DebuggerDisplay("Key = {Key}, Secret = {Secret}")]
    [DataContract]
    public abstract class Token : BaseToken
    {
        [DataMember(Order = 1)]
        public string Key { get; private set; }
        [DataMember(Order = 2)]
        public string Secret { get; private set; }

        /// <summary>for serialize.</summary>
        [Obsolete("this is used for serialize")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Token()
        { }

        public Token(string key, string secret, ILookup<string, string> extraData)
        {
            Precondition.NotNull(key, "key");
            Precondition.NotNull(secret, "secret");

            this.Key = key;
            this.Secret = secret;
            this.ExtraData = extraData;
        }
    }

    /// <summary>represents OAuth AccessToken</summary>
    [DataContract]
    public class AccessToken : Token
    {
        /// <summary>for serialize.</summary>
        [Obsolete("this is used for serialize")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public AccessToken()
        { }

        public AccessToken(string key, string secret, ILookup<string, string> extraData)
            : base(key, secret, extraData)
        { }
    }

    /// <summary>represents OAuth RequestToken</summary>
    [DataContract]
    public class RequestToken : Token
    {
        /// <summary>
        /// for serialize.
        /// </summary>
        [Obsolete("this is used for serialize")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public RequestToken()
        { }

        public RequestToken(string key, string secret, ILookup<string, string> extraData)
            : base(key, secret, extraData)
        { }
    }
}

#pragma warning restore 612, 618