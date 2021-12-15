using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DatabaseMirroringAuthentication.Utilities
{
    /// <summary>
    /// Class for handling public and private keys related to Partner Applications. 
    /// </summary>
    public class ApplicationKeys
    {

        /// <summary>
        /// The algorithm used for signing and verifying signed data. 
        /// </summary>
        public const string SignatureAlgorithm = "SHA256";


        /// <summary>
        /// Get the public key as XML
        /// </summary>
        public string PublicKeyXml { get; private set; }


        /// <summary>
        /// Initializes a new instance of PartnerKey with the supplied publicKeyXml. 
        /// </summary>
        /// <param name="publicKeyXml"></param>
        public ApplicationKeys(string publicKeyXml)
        {
            if (string.IsNullOrWhiteSpace(publicKeyXml))
                throw new ArgumentNullException("publicKeyXml");

            PublicKeyXml = publicKeyXml;
        }


        /// <summary>
        /// Validate the data based on the supplied signature. The signature must be based on the SignatureAlgorithm. 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public bool ValidateSignature(byte[] data, byte[] signature)
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.FromXmlString(PublicKeyXml);

                return rsaCryptoServiceProvider.VerifyData(data, SignatureAlgorithm, signature);
            }
        }

    }
}
