using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DatabaseMirroringAuthentication.Utilities
{
    /// <summary>
    /// Handle the parts of the system token and implement correct validation of the data.     
    /// 
    /// The system token must have the following structure:
    /// SystemToken.Timestamp.BASE64(Signature)  
    /// </summary>
    public class TokenData
    {
        public const int MaxAllowedDrift = 15;

        public string Nonce { get; set; }
        public string Timestamp { get; set; }
        public byte[] Signature { get; set; }

        public string Raw { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rawData">Signed token sent by application</param>
        public TokenData(string rawData)
        {
            Process(rawData);
        }

        private void Process(string rawData)
        {
            try
            {
                Raw = rawData;

                var parts = Raw.Split('.');
                if (parts.Length == 3)
                {
                    Nonce = parts[0];
                    Timestamp = parts[1];

                    Signature = Convert.FromBase64String(parts[2]);
                }
            }
            catch (Exception)
            {
                // Invalid data.
                Nonce = string.Empty;
                Timestamp = string.Empty;
                Signature = null;
            }
        }

        /// <summary>
        /// Validate the token with respect to the current datetime and the signature
        /// </summary>
        /// <param name="applicationKey"></param>
        /// <returns></returns>
        public bool Validate(ApplicationKeys applicationKey)
        {
            if (string.IsNullOrEmpty(Nonce) ||
                string.IsNullOrEmpty(Timestamp) ||
                Signature == null || !Signature.Any())
                return false;

            if (!HasValidTimestamp)
                return false;

            var dataToValidate = Nonce + "." + Timestamp;
            return applicationKey.ValidateSignature(Encoding.UTF8.GetBytes(dataToValidate), Signature);
        }

        /// <summary>
        /// Check if the supplied timestamp is valid when this code is executed. There is support for MaxAllowedDrift between the timestamp and the current time.         
        /// The timestamp is expected to be in the format "yyyyMMddHHmm" => 201401012301 and in UTC.  
        /// </summary>
        public bool HasValidTimestamp
        {
            get
            {
                if (string.IsNullOrWhiteSpace(Timestamp))
                    return false;

                var now = DateTime.UtcNow;
                DateTime timestamp;

                if (!DateTime.TryParseExact(Timestamp, "yyyyMMddHHmm", null, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out timestamp))
                    return false;

                var diff = timestamp - now;

                return Math.Abs(diff.TotalMinutes) < MaxAllowedDrift;
            }
        }
    }
}
