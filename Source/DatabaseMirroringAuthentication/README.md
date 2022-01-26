# Database Mirroring Authentication Example

This sample application demonstrates the cryptographic requirements for manually testing SuperOffice database mirroring.

Review the code in program.cs file to gain a better understanding of the flow and procedure.

There are two types of cryptographic files used in this sample:

1. Self-signed certificate, public-private key pair, simulates the SuperOffice public and private certificate used to sign and validate requests.
   1. SuperOfficeCertificates\DevNet.key
   2. SuperOfficeCertificates\DevNet.crt.
2. RSA XML public-private files that are normally issued by SuperOffice to the application vendor.
   1. The private RSA key is used to sign requests sent to SuperOffice.
   2. The public RSA key is used by SuperOffice to validate requests sent from the application.
   3. In this example, these are generated in-memory when the application runs, but should be saved to disk when simulating real world scenario.

## Database Mirror Server - Prepares Request

Prior to sending an authentication request, SuperOffice will generate a nonce that the service must return in the response. The token generator will also include the tenant identifier and application ID (client_id) in the generated token.

```csharp
// This nonce is stored as one of the claims in the token.
// It must be included in the response from the service.

string nonce;

var tokenGenerator = new JwtTokenGenerator();
var signedToken = tokenGenerator.CreateSignedSuperIdToken(
    "Cust12020", 
    "123123123123123123",
    out nonce);
```

The resulting token contains the following payload.

```json
{
  "sub": "Cust12020",
  "nonce": "6D50C131F468876F5B316273B20B69FE",
  "http://schemes.superoffice.net/identity/ctx": "Cust12020",
  "nbf": 1639643167,
  "exp": 1639643527,
  "iss": "SuperOffice AS",
  "aud": "spn:123123123123123123"
}
```

The generated token is then placed in the SignedToken header element of the SOAP envelope.

### Sends AuthenticateRequest

> HTTP Request

```http
POST https://YOUR-DB-MIRRORING-URL/Authenticate HTTP/1.1
Content-Type: text/xml;charset=UTF-8
SOAPAction: http://www.superoffice.com/online/mirroring/0.1/IMirroringClientService/Authenticate
```

> Request body:

```xml
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Header>
    <SignedToken s:mustUnderstand="1" xmlns="http://www.superoffice.com/online/mirroring/0.1">eyJhbGciOiJSUzI1NiIsImtpZCI6IkIwQUQ0QzBCRkQ4OTEzQjgwNDBGM0U4QUQxNkE5MUY1ODUyMjJDMzMiLCJ4NXQiOiJzSzFNQ18ySkU3Z0VEejZLMFdxUjlZVWlMRE0iLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJDdXN0MTIwMjAiLCJub25jZSI6IjlBQjQxNDkzNzYyQjBDNUI2RTBGMUFCMzVGMDMyQjk1IiwiaHR0cDovL3NjaGVtZXMuc3VwZXJvZmZpY2UubmV0L2lkZW50aXR5L2N0eCI6IkN1c3QxMjAyMCIsIm5iZiI6MTYzOTY0MDM4MSwiZXhwIjoxNjM5NjQwNzQxLCJpc3MiOiJTdXBlck9mZmljZSBBUyIsImF1ZCI6InNwbjoxMjMxMjMxMjMxMjMxMjMxMjMifQ.UcpcXF3Pg8anUmb5YuZ3cKlcoIHpZ7a4PwRHZ2A4JUWX5TN74QK7uCWo6OyaVBxKul-6KqcXEWDuzLv5fNRt12ZxTyyhqxVQSNou4mHu-dDxysjgLSrKqoWQr500CafbAS_6U6-7sPEvftRq9SzkGqQQP-bnEtWR9vezdaB9LYTLDuw9G-u-FncB_SYHPD0TNCe5pY_sZArNL4oEhVqcvZ97HX3GveUDjv1J0BNNnXQHkTVuwZ0og_qDppqNS_SXTqSUqolsxZgLrPvKWDATiLJoNDBgZuYTpWciDKp1Q0L9oBR5LSMZ8-xuyFu6Icw88_hTOz5vyOXmRCxzCJNUrg</SignedToken>
</s:Header>
<s:Body>
    <AuthenticateRequest xmlns="http://www.superoffice.com/online/mirroring/0.1">
        <ClientState/>
    </AuthenticateRequest>
</s:Body>
</s:Envelope>
```

## Database Mirroring Service - Receives AuthenticateRequest

Now it's up to the receiving service to extract and validate the signed token from the SOAP header, then send a signed response.

```csharp
// validate SuperOffice signed token

var validator = new Validator();
var result = validator.ValidateSuperOfficeToken(signedToken);
```

The result is a Microsoft.IdentityModel.Tokens.TokenValidationResult. If the result.IsValid property is false, then the service returns an AuthenticateResponse that states IsSuccessful as false, with the ErrorMessage element populated with the exception message.

If the result.IsValid property is true, then the service must use its private RSAXML key to sign a string to populate the SignedApplicationToken element.

The example contains the following code that generates the applications signed token. It needs the nonce, that was issued by the Database Mirroring Server, and the **private RSA** key that was issued provided by SuperOffice when the application was registered. In this example though, it was generated and stored inmemory when the application runs. See _Program.cs_, **line 15**.

```csharp
// generate simulated application signed token

string appSignedToken = tokenGenerator.CreateSignedApplicationToken(
    nonce,
    privateRsaKey
    );
```

The signed application token contains a period-delimited string that contains the following information.

- Nonce
- Current date and time
- Signed representation of Nonce and current date and time.

The response must state that IsSuccessful is true, and populate the SignedApplicationToken element with the appSignedToken value.

```xml
<s:Envelope
    xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <AuthenticateResponse
            xmlns="http://www.superoffice.com/online/mirroring/0.1">
            <IsSuccessful>true</IsSuccessful>
            <ErrorMessage/>
            <SignedApplicationToken>BDB65A558F193A8DD88E50E7416C0D86.202109161125.OKNE8l9YOXm4AJRCfzNx4egvU/jTjwii6XU+fM2P6bFjQpYSBi0w4VH0dN82CQdWEkcuGW9yjsLU82za08myMWelFKWvwqIY0oaaTYAPzhj27JNa5OZw3tUc1zunR7DrwpLSkwC3cEK3s3u3VDN8GKoMMeQVOogxS7f1hT3a4/Q=</SignedApplicationToken>
            <SupportedInterfaces>1</SupportedInterfaces>
            <SuperOfficeMirroringBuild>4.0.0.0/Release_1</SuperOfficeMirroringBuild>
            <ClientState/>
            <AdditionalInformationJson/>
        </AuthenticateResponse>
    </s:Body>
</s:Envelope>
```

## Database Mirroring Server - Receives response

The database mirring server now receives the response from the service and must validate it.

The server reads the AuthenticateResponse and extracts the SignedApplicationToken.

Using the applications public RSA xml key, SuperOffice validates the signed application token.

```csharp
var valid = validator.ValidatePartnerToken(
    publicRsaKey,
    appSignedToken,
    nonce
    );
```

If the result of ValidatePartnerToken is a true, then SuperOffice will begin sending subsequent Database Mirroring messages, such as TableSchemaRequest and so forth. That is not covered in this example.
