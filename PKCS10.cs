using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace pkcs10gen
{
    class Program
    {
        public static AsymmetricCipherKeyPair MakeKeyPair()
        {
            RsaKeyPairGenerator rsaGen = new RsaKeyPairGenerator();

            rsaGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            AsymmetricCipherKeyPair keyPair = rsaGen.GenerateKeyPair();

            return keyPair;
        }

        static void Main(string[] args)
        {
        }
    }
}
