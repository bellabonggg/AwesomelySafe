package encryption;

import constants.FilePaths;

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


    /**
     * Verifies two certificates by file path
     * @param caCertPath
     * @param serverFilePath
     * @return true if verified, false otherwise
     * @throws FileNotFoundException
     * @throws CertificateException
     */
    public static boolean verifyCertificate(String caCertPath, String serverFilePath) throws FileNotFoundException, CertificateException {

        InputStream caInputStream = new FileInputStream(caCertPath);
        InputStream serverCertInputStream = new FileInputStream(serverFilePath);

        X509Certificate caCertificate = X509Certificate.getInstance(caInputStream);
        X509Certificate serverCertificate = X509Certificate.getInstance(serverCertInputStream);

        return verifyCertificate(caCertificate, serverCertificate);


    }

    /**
     * Verifies two certificates
     * @param caCert
     * @param serverCert
     * @return true if verified, false otherwise
     * @throws CertificateException
     */
    public static boolean verifyCertificate(X509Certificate caCert, X509Certificate serverCert) throws CertificateException {

        PublicKey caCertificatePublicKey = caCert.getPublicKey();

        serverCert.checkValidity();

        boolean result = true;
        try {
            serverCert.verify(caCertificatePublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            result = false;
        }

        return result;
    }


    public static void main(String[] args) throws FileNotFoundException, CertificateException {

        final String CA_CERT_NAME = FilePaths.CA_CERTIFICATE;
        final String SERVER_CERT_NAME = FilePaths.SERVER_CERTIFICATE;


        verifyCertificate(CA_CERT_NAME, SERVER_CERT_NAME);
    }

}
