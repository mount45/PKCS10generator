using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Collections;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using System.IO;

//
// Simple demo of generating a PKCS#10 with C#.
//
namespace pkcs10gen
{
    class Program
    {
        public static AsymmetricCipherKeyPair MakeKeyPair()
        {
            RsaKeyPairGenerator rsaGen = new RsaKeyPairGenerator();

            rsaGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = rsaGen.GenerateKeyPair();

            return keyPair;
        }


        static void Main(string[] args)
        {

            IDictionary attrs = new Hashtable();

            attrs.Add(X509Name.C, "GB");
            attrs.Add(X509Name.O, "Red Kestrel");
            attrs.Add(X509Name.CN, "Phil Ratcliffe");
            
            X509Name subject = new X509Name(new ArrayList(attrs.Keys), attrs);

            AsymmetricCipherKeyPair pair = MakeKeyPair();
            
            Asn1SignatureFactory sigFact = new Asn1SignatureFactory("SHA1withRSA", pair.Private, new SecureRandom());

            // Create the PKCS10 CSR.
            Pkcs10CertificationRequest req = new Pkcs10CertificationRequest(
                sigFact,
                subject,
                pair.Public,
                null,
                pair.Private);

            //
            // Convert BouncyCastle CSR to PEM string and write to Console.
            //
            StringBuilder CSRPem = new StringBuilder();
            PemWriter CSRPemWriter = new PemWriter(new StringWriter(CSRPem));
            CSRPemWriter.WriteObject(req);
            CSRPemWriter.Writer.Flush();
            Console.Write(CSRPem);


        }
    }
}
