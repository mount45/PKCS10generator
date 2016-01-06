
import java.security.Security;

/**
 * Class to confirm the Bouncy Castle provider is installed.
 * Make sure you have added Bouncy Castle to the java.security file first.
 * Also add Bouncy Castle jars to jre/lib/ext directory.
 *
 * e.g., security.provider.N=org.bouncycastle.jce.provider.BouncyCastleProvider
 */
public class ProviderTest
{
    public static void main(String[] args)
    {
        String providerName = "BC";

        if (Security.getProvider(providerName) == null)
        {
            System.out.println(providerName + " provider not installed");
        }
        else
        {
            System.out.println(providerName + " is installed.");
        }
    }
}
