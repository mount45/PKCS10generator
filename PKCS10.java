import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.io.OutputStreamWriter;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider; 
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;


/**
 * A class that generates PKCS10 certificate signing requests for testing
 * purposes only.
 * 
 * The code requires that the bouncycaslte jars are on the CLASSPATH or
 * in the jre/lib/ext directory.
 *
 * For example:
 *     To put the BC libs on the CLASSPATH you could do this:
 * 
 *     copy bcprov-ext-jdk15on-153.jar, bcprov-jdk15on-153.jar, and
 *     bcpkix-jdk15on-153.jar to ~/jars
 * 
 *     export CLASSPATH=.:$CLASSPATH:~/jars/*
 *
 */

public class PKCS10 {
 
    public static int RSA_KEYSIZE = 2048;

    public static void main(String[] args) throws Exception {
 
        Security.addProvider(new BouncyCastleProvider());

        //
        // Generate an RSA key pair.
        //

        // Initialise a secure random number generator.
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "BC");
        
        // Call nextBytes to cause the PRNG to be seeded using a secure 
        // mechanism provided by the underlying operating system.
        byte[] bytes = new byte[512];
        sr.nextBytes(bytes); 

        // Now that we have handled setting up the PRNG, lets generate the 
        // RSA keypair.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEYSIZE, sr);
        KeyPair kp = keyGen.genKeyPair();


        //
        // Generate the PKCS#10 CSR. This is just a simple CSR containing a public key and DN. 
        //
        JcaPKCS10CertificationRequestBuilder builder = 
            new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("cn=Phil Ratcliffe, o=Red Kestrel"), 
                kp.getPublic()
            );
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        PKCS10CertificationRequest csr = builder.build(signerBuilder.build(kp.getPrivate()));

        OutputStreamWriter output = new OutputStreamWriter(System.out);
        JcaPEMWriter pem = new JcaPEMWriter(output);
        pem.writeObject(csr);
        pem.close();
    }
 
}
