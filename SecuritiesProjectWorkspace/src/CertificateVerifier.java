import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;


/**
 * Created by JiaHao on 16/4/15.
 */
public class CertificateVerifier {


    public static boolean verifyCertificate(String caCertPath, String serverFilePath) throws FileNotFoundException, CertificateException {

        InputStream inputStream = new FileInputStream(caCertPath);


        X509Certificate caCertificate = X509Certificate.getInstance(inputStream);

        inputStream = new FileInputStream(serverFilePath);


        X509Certificate serverCertificate = X509Certificate.getInstance(inputStream);

        PublicKey caCertificatePublicKey = caCertificate.getPublicKey();

        serverCertificate.checkValidity();

        boolean result = true;
        try {
            serverCertificate.verify(caCertificatePublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            result = false;
        }

        return result;
    }

    public static void main(String[] args) throws FileNotFoundException, CertificateException {

        final String CA_CERT_NAME = "src/CA.crt";
        final String SERVER_CERT_NAME = "src/server.crt";


        verifyCertificate(CA_CERT_NAME, SERVER_CERT_NAME);
    }

}
