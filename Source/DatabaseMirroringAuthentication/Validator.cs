using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using DatabaseMirroringAuthentication.Utilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace DatabaseMirroringAuthentication
{
    internal class Validator
    {
        /// <summary>
        /// Validates the token supplied by the partner. 
        /// </summary>
        /// <param name="publicKey">RSA XML string</param>
        /// <param name="token">Signed token sent by application</param>
        /// <param name="nonce">The nonce</param>
        /// <returns></returns>
        public virtual bool ValidatePartnerToken(string publicKey, string token, string nonce)
        {
            var signingData = new TokenData(token);
            var signatureIsOk = signingData.Validate(new ApplicationKeys(publicKey));
            return (signatureIsOk && signingData.Nonce == nonce);
        }

        public TokenValidationResult ValidateSuperOfficeToken(string token)
        {
            var SecurityTokenHandler = new JsonWebTokenHandler();
            
            string issuer;
            string audience;

            // extract the ValidAudience claim value (database serial number). 
            var securityToken = SecurityTokenHandler.ReadJsonWebToken(token);

            // get the audience from the token
            if (!securityToken.TryGetPayloadValue<string>("aud", out audience))
            {
                throw new SecurityTokenException("Unable to read ValidAudience from System User token.");
            }

            // get the issuer from the token
            if (!securityToken.TryGetPayloadValue<string>("iss", out issuer))
            {
                throw new SecurityTokenException("Unable to read ValidAudience from System User token.");
            }

            // use the local SuperOffice public certificate (SuperOfficeFederatedLogin)
            
            var certPath = Path.Combine("SuperOfficeCertificate", "DevNet.crt");
            var x509Cert = new X509Certificate2(certPath);

            var validationParameters = new TokenValidationParameters();
            validationParameters.ValidAudience = audience;
            validationParameters.ValidIssuer = issuer;
            validationParameters.IssuerSigningKey = new X509SecurityKey(x509Cert);

            var result = SecurityTokenHandler.ValidateToken(token, validationParameters);

            if (result.Exception != null || !result.IsValid)
            {
                throw new SecurityTokenValidationException("Failed to validate the token", result.Exception);
            }
            return result;
        }
    }
}
