package authentication;

import AwesomeSockets.AwesomeClientSocket;
import AwesomeSockets.AwesomeServerSocket;
import Tests.TestEncryptDecrypt;
import encryption.CertificateVerifier;
import encryption.EncryptDecryptHelper;
import encryption.FilePaths;
import encryption.SecurityFileReader;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.IllegalFormatCodePointException;

/**
 * Created by JiaHao on 19/4/15.
 */
public class APClient {

    private final AwesomeClientSocket clientSocket;

    private byte[] serverHelloMessage;

    public APClient() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.clientSocket = new AwesomeClientSocket(AuthenticationConstants.SERVER_IP, AuthenticationConstants.PORT);

    }


    public void start() throws IOException {
        authenticationProtocol();

    }

    public void authenticationProtocol() throws IOException {
        try {
            sendHelloToServer();
            askServerForCertificate();
            sendToServerSymmetricKey();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            System.err.println(e);
            this.closeClient();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }


    }

    private void sendHelloToServer() throws IOException, IllegalAccessException {

        System.out.println("Sending hello to server...");
        this.clientSocket.sendMessageLine(AuthenticationConstants.CLIENT_HELLO_MESSAGE);

        this.serverHelloMessage = this.clientSocket.readByteArray();

//        if (!receivedMessage.equals(AuthenticationConstants.SERVER_REPLY_TO_HELLO)) {
//
//            throw new IllegalAccessException("Server did not reply to hello");
//        }

    }
    private void askServerForCertificate() throws IOException, CertificateException, IllegalAccessException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        // todo nonce
        System.out.println("Asking server for certificate...");
        this.clientSocket.sendMessageLine(AuthenticationConstants.CLIENT_ASK_FOR_CERT);

        byte[] receivedCertificate = this.clientSocket.readByteArray();


        X509Certificate serverCert = X509Certificate.getInstance(receivedCertificate);
        InputStream caCertInputStream = new FileInputStream(FilePaths.CA_CERTIFICATE);
        X509Certificate caCert = X509Certificate.getInstance(caCertInputStream);

        if (!CertificateVerifier.verifyCertificate(caCert, serverCert)) {
            throw new IllegalAccessException("Cannot verify certificate");
        } else {
            System.out.println("Server certificate is verified.");


            Key serverPublicKey = serverCert.getPublicKey();

            Cipher decryptCipher = EncryptDecryptHelper.getDecryptCipher(serverPublicKey);


            String serverDecryptedMessage = EncryptDecryptHelper.decryptMessage(this.serverHelloMessage, decryptCipher);

            System.out.println(serverDecryptedMessage);
            if (!serverDecryptedMessage.equals(AuthenticationConstants.SERVER_REPLY_TO_HELLO)) {
                throw new IllegalAccessException("Cannot verify server hello message!");
            }

        }
    }
    private void sendToServerSymmetricKey() {
        System.out.println("Sending symmetric key to server");
        // todo symmetric key generation
    }


    private void closeClient() throws IOException {

        this.clientSocket.sendMessageLine(AuthenticationConstants.BYE);
        this.clientSocket.closeClient();

    }


    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        APClient client = new APClient();
        client.start();
    }
}
