import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.io.OutputStreamWriter;
import java.io.FileReader;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider; 
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;


/**
 * A class that decodes a PKCS10 certificate signing request.
 *
 * The code requires that the bouncycaslte jars are on the CLASSPATH or
 * in the jre/lib/ext directory.
 *
 * For example:
 *     copy bcprov-ext-jdk15on-153.jar, bcprov-jdk15on-153.jar, and
 *     bcpkix-jdk15on-153.jar to ~/jars
 *     export CLASSPATH=.:$CLASSPATH:~/jars/*
 *
 */

public class PKCS10Decoder {

    public static int RSA_KEYSIZE = 2048;

    public static void main(String[] args) throws Exception {

        String csrFilename;

        if (args.length < 1)
        {
            csrFilename = "csr";
        }
        else
        {
            csrFilename = args[0];
        }
        PemReader reader = new PemReader(new FileReader(csrFilename));
        PemObject pemObject = reader.readPemObject();
        reader.close();

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pemObject.getContent());

        OutputStreamWriter output = new OutputStreamWriter(System.out);
        JcaPEMWriter pem = new JcaPEMWriter(output);
        pem.writeObject(csr);
        pem.close();
    }

}
