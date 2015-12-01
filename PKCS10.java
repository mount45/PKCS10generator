import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider; 
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 * A class that generates PKCS10 certificate signing requests
 * 
 * Need the bouncycaslte jars on CLASSPATH:
 * For example:
 *     copy bcprov-ext-jdk15on-153.jar and bcprov-jdk15on-153.jar to ~/jars
 *     export CLASSPATH=.:$CLASSPATH:~/jars/*
 *
 */
public class PKCS10 {
 
    public static int RSA_KEYSIZE = 2048;

    public static void main(String[] args) throws Exception {
 
        Security.addProvider(new BouncyCastleProvider());

        // Generate an RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEYSIZE, new SecureRandom());
        KeyPair kp = keyGen.genKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("cn=phil"), kp.getPublic());
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        builder.build(signerBuilder.build(kp.getPrivate()));
    }
 
}
