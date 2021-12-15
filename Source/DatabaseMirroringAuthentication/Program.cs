using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace DatabaseMirroringAuthentication
{

    public class Program
    {
        static void Main(string[] args)
        {
            // generate the applications public and private keys (RSAXML)

            var keys = KeyGenerator.Generate();

            Console.WriteLine("Public key:");
            Console.WriteLine();
            Console.WriteLine(keys.Key);
            Console.WriteLine();
            Console.WriteLine("Private key:");
            Console.WriteLine();
            Console.WriteLine(keys.Value);
            Console.WriteLine();

            // NONCE is require to send to the client, AND to sign the clients response token.

            string nonce = string.Empty;

            // pretend to be SuperOffice and generate signed token

            var authenticator = new JwtTokenGenerator();
            var signedToken = authenticator.CreateSignedSuperIdToken(
                "Cust12020", 
                "123123123123123123", 
                out nonce);

            Console.WriteLine("SuperOffice signed token:");
            Console.WriteLine(signedToken);
            Console.WriteLine();

            //SEND SOAP AuthenticateRequest ENVELOPE WITH SignedToken HEADER

            //EXTRACT the SignedToken from the HEADER

            // validate SuperOffice signed token

            var validator = new Validator();
            var result = validator.ValidateSuperOfficeToken(signedToken);

            Console.WriteLine(string.Format("Application validation of SuperOffice token was {0}", result.IsValid ? "successful!" : "not successful!"));
            Console.WriteLine();

            // generate simulated application signed token

            string appSignedToken = authenticator.CreateSignedApplicationToken(
                nonce,
                keys.Value
                );


            Console.WriteLine("Application signed token:");
            Console.WriteLine(appSignedToken);
            Console.WriteLine();

            // pretend to be SuperOffice and validate Application signed token

            var valid = validator.ValidatePartnerToken(
                keys.Key,
                appSignedToken,
                nonce
                );

            Console.WriteLine(string.Format("SuperOffice validation of application token was {0}", valid ? "successful!" : "not successful!"));
            Console.WriteLine();

            Console.WriteLine("Press any key to quit...");
            Console.ReadKey();
        }
    }

}



