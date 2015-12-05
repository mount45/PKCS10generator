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

            attrs.Add(X509Name.C, "AU");
            attrs.Add(X509Name.O, "The Legion of the Bouncy Castle");
            attrs.Add(X509Name.L, "Melbourne");
            attrs.Add(X509Name.ST, "Victoria");
            attrs.Add(X509Name.EmailAddress, "feedback-crypto@bouncycastle.org");

            X509Name subject = new X509Name(new ArrayList(attrs.Keys), attrs);

            AsymmetricCipherKeyPair pair = MakeKeyPair();
            Asn1SignatureFactory sigFact = new Asn1SignatureFactory("SHA1withRSA", pair.Private, new SecureRandom());

            Pkcs10CertificationRequest req1 = new Pkcs10CertificationRequest(
                sigFact,
                subject,
                pair.Public,
                null,
                pair.Private);

        }
    }
}
