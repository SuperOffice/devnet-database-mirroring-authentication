# Database Mirroring Authentication Example

This sample application demonstrates the cryptographic requirements for manually testing SuperOffice database mirroring.

Review the code in program.cs file to gain a better understanding of the flow and procedure.

There are two types of cryptographic files used in this sample:

1. Self-signed certificate, public-private key pair, used to represent the SuperOffice public and private certificate used to sign and validate requests.
2. RSA XML public-private files that are issues to the application by SuperOffice, and used to sign responses with the private key. SuperOffice uses the public side to validate application signed responses.
