import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.io.FileOutputStream;
import java.io.FileReader;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;



public class CsrPEMtoDER {

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

        // Read CSR from file
        PemReader reader = new PemReader(new FileReader(csrFilename));
        PemObject pemObject = reader.readPemObject();
        reader.close();

        // Create a BC P10 request object
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pemObject.getContent());

        // Write the DER encoded request to a file
        FileOutputStream output = new FileOutputStream("csr.der");
        output.write(csr.getEncoded());
        output.close();
    }

}
