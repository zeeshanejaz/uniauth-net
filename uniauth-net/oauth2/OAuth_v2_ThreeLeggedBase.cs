using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AsyncOAuth.OAuth2;

namespace uniauth_net.oauth2
{
    public abstract class OAuth_v2_ThreeLeggedBase : OAuth_v2_Base
    {
        protected string accessTokenUrl = null;
        protected string clientSecret = null;

        public OAuth_v2_ThreeLeggedBase(string clientId, string clientSecret,
            string redirectUrl, string scope, string authorizationUrl, string accessTokenUrl)
            : base(clientId, redirectUrl, scope, authorizationUrl)
        {
            this.accessTokenUrl = accessTokenUrl;
            this.clientSecret = clientSecret;
        }

        /// <summary>
        /// Refresh access token flow if the refrsh token was issued
        /// </summary>
        /// <returns>True, if successful</returns> 
        public async Task<bool> RefreshAccessToken()
        {
            //initialize the underlying OAuthorizer
            if (oauthorizer == null)
                initOAuthorizer(clientSecret);

            if (OAuthState != OAuthState.SUCCEEDED)
            {
                throw new InvalidOperationException("The request must be authorized before refresh.");
            }

            if (AccessToken == null)
            {
                throw new InvalidOperationException("The access token has not previously been acquired.");
            }

            if (string.IsNullOrWhiteSpace(AccessToken.RefreshToken))
            {
                throw new InvalidOperationException("Refresh token was not found.");
            }

            OAuthState = OAuthState.REFRESH_WAIT;

            var parameters = new List<KeyValuePair<string, string>>(capacity: 6)
                {
                    new KeyValuePair<string,string>(Constants.REFRESH_TOKEN, this.AccessToken.RefreshToken),
                    new KeyValuePair<string,string>(Constants.CLIENT_SECRET, this.clientSecret)
                };

            var accessTokenUrl = oauthorizer.BuildAuthorizeUrl(authorizationUrl, Constants.GRANT_TYPE_REFRESH_TOKEN, parameters);
            Uri authUri = new Uri(accessTokenUrl);

            OAuthState = OAuthState.ACCESS_TOKEN_WAIT;
            try
            {
                var result = await oauthorizer.GetAccessTokenAsync(accessTokenUrl);

                if (result != null)
                {
                    OAuthState = OAuthState.SUCCEEDED;
                    var token = result.Token;
                    base.RestoreAccessToken(token.Code, token.Expires, token.RefreshToken);

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
