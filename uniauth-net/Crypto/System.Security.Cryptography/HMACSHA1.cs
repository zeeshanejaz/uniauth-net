/***********************************************************************************************
* This license is an adaptation of the MIT X11 (http://opensource.org/licenses/mit-license.php) 
* License and should be read as such.
* 
* Copyright (c) 2014 APIMatic Inc.
* Adopted from The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software
* and associated documentation files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or
* substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
* BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
* DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 **********************************************************************************************/

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace System.Security.Cryptography
{
    internal class HMACSHA1 : IDisposable
    {
        public byte[] Key {get ; private set;}
        private HMac hmac = null;
        private byte[] resBuf = null;

        public HMACSHA1(byte[] key)
        {
            this.Key = key;
        }

        public byte[] ComputeHash(byte[] input)
        {
            hmac = new HMac(new Sha1Digest());
            resBuf = new byte[hmac.GetMacSize()];
            hmac.Init(new KeyParameter(Key));
            hmac.BlockUpdate(input, 0, input.Length);
            hmac.DoFinal(resBuf, 0);
            input = null;
            return resBuf;
        }

        public void Dispose()
        {
            Key = null;
            hmac = null;
            resBuf = null;
        }
    }
}
