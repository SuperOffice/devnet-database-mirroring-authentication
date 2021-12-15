using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DatabaseMirroringAuthentication
{
    internal class JwtTokenGenerator
    {
        /// <summary>
        /// Sign the token according to the system user specification.                  
        /// </summary>
        /// <param name="nonce">The nonce passed to the service from SuperOffice.</param>
        /// <param name="privateKey">XML Formatted RSA public key.</param>
        /// <returns>Signed system user string.</returns>
        internal string CreateSignedApplicationToken(string nonce, string privateKey)
        {
            var utcNow = DateTime.UtcNow.ToString("yyyyMMddHHmm");
            var signThis = nonce + "." + utcNow;
            using (var rsaCryptoProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoProvider.FromXmlString(privateKey);
                var signature = rsaCryptoProvider.SignData(Encoding.UTF8.GetBytes(signThis), "SHA256");
                return signThis + "." + Convert.ToBase64String(signature);
            }
        }

        /// <summary>
        /// Creates a signed token to be used for authenticating against a partner service.
        /// </summary>
        /// <param name="contextIdentifier">Context identifier of customer</param>
        /// <param name="applicationIdentifier">Application identifier of receiving partner application</param>
        /// <param name="claims">Claims to add to the token.</param>
        /// <param name="nonce">A random nonce - should be used for validating the response.</param>
        /// <returns></returns>
        public string CreateSignedSuperIdToken(string contextIdentifier, string applicationIdentifier, out string nonce)
        {
            nonce = CreateNonce();
            var claims = new List<Claim>
             {
                 new Claim("nonce", nonce),
                 new Claim("http://schemes.superoffice.net/identity/ctx", contextIdentifier)
             };

            var token = GenerateToken("spn:" + applicationIdentifier, contextIdentifier, claims);
            return token;
        }

        private string GenerateToken(string audience, string spn, IEnumerable<Claim> claims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var totalClaims = new[] { new Claim(JwtRegisteredClaimNames.Sub, spn) }.Union(claims);

            var token = new JwtSecurityToken(
                "SuperOffice AS", 
                audience, 
                totalClaims, 
                DateTime.Now.AddMinutes(-1), 
                DateTime.Now.AddMinutes(5),
                GetSigningCredentials()
                );
            
            return tokenHandler.WriteToken(token);
        }

        private static SigningCredentials GetSigningCredentials()
        {
            var x509Cert = X509Certificate2.CreateFromPemFile(
                Path.Combine(Environment.CurrentDirectory, "SuperOfficeCertificate", "DevNet.crt"),
                Path.Combine(Environment.CurrentDirectory, "SuperOfficeCertificate", "private.key")
                );
            
            return new X509SigningCredentials(x509Cert, SecurityAlgorithms.RsaSha256);
        }

        /// <summary>
        /// Creates a 32 random string (only 16 byte entropy).
        /// </summary>
        /// <returns></returns>
        private static string CreateNonce()
        {
            using (var rg = RandomNumberGenerator.Create())
            {
                var bytes = new byte[16];
                rg.GetBytes(bytes);

                var sb = new StringBuilder();
                foreach (var b in bytes)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }
        }

    }
}