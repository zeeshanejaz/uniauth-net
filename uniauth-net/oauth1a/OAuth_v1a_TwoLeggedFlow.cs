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

using System;
using System.Threading.Tasks;

namespace uniauth_net.oauth1a
{
    public class OAuth_v1a_TwoLeggedFlow : OAuth_v1a_Base
    {
        protected string requestTokenUrl = null;        
        protected string accessTokenUrl = null;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <param name="callbackUrl"></param>
        /// <param name="requestTokenUrl"></param>
        /// <param name="accessTokenUrl"></param>
        public OAuth_v1a_TwoLeggedFlow(string clientId, string clientSecret,
            string callbackUrl, string requestTokenUrl, string accessTokenUrl)
            :base(clientId, clientSecret, callbackUrl)
        {
            this.requestTokenUrl = requestTokenUrl;            
            this.accessTokenUrl = accessTokenUrl;
        }

        /// <summary>
        /// Takes user authorization viewer and invokes the OAuth1a 2-legged flow
        /// </summary>
        /// <param name="viewer">The authorization viewer</param>        
        public virtual async Task<bool> InvokeUserAuthorization()
        {
            //initialize the underlying OAuthorizer
            initOAuthorizer();

            try
            {
                OAuthState = OAuthState.REQUEST_TOKEN_WAIT;
                var token = await getRequestToken(requestTokenUrl);

                OAuthState = OAuthState.ACCESS_TOKEN_WAIT;
                var result = await oauthorizer.GetAccessTokenAsync(accessTokenUrl, requestToken);

                if (result != null)
                {
                    OAuthState = OAuthState.SUCCEEDED;
                    AccessToken = result.Token;
                    return true;
                }
                else
                {
                    OAuthState = OAuthState.FAILED;
                    return false;
                }
            }
            catch (Exception ex)
            {
                OAuthState = OAuthState.FAILED;
                throw ex;
            }
        }
    }
}


