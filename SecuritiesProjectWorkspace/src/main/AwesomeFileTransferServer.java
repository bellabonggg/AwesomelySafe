package main;


import AwesomeSockets.AwesomeServerSocket;
import constants.AuthenticationConstants;
import encryption.EncryptDecryptHelper;
import constants.FilePaths;
import encryption.SecurityFileReader;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by JiaHao on 19/4/15.
 */
public class AwesomeFileTransferServer {

    private final AwesomeServerSocket serverSocket;
    private final Cipher encryptCipher;

    public AwesomeFileTransferServer() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.serverSocket = new AwesomeServerSocket(AuthenticationConstants.PORT);
        this.encryptCipher = EncryptDecryptHelper.getEncryptCipher(FilePaths.SERVER_PRIVATE_KEY);
    }

    public void start() throws IOException {
        this.serverSocket.acceptClient();

        authenticationProtocol();
        confidentialityProtocol();
    }

    public void authenticationProtocol() {
        System.out.println("=== AUTHENTICATION PROTOCOL ===");
        // todo error catching

        try {
            waitForClientToSayHello();
            waitForClientToAskForCertificate();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void confidentialityProtocol() {
        System.out.println("=== CONFIDENTIALITY PROTOCOL ===");

        // todo by Pablo

        try {
            waitForClientToSendSymmetricKey();
            waitForClientToSendFile();

            // etc

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private void waitForClientToSayHello() throws IOException {
        System.out.println("Waiting for client to say hello...");
        // wait for client to say hello
        boolean clientSaidHello = false;

        while (!clientSaidHello) {

            String clientMessage = this.serverSocket.readMessageLineForClient(0);

            if (clientMessage.equals(AuthenticationConstants.CLIENT_HELLO_MESSAGE)) {
                clientSaidHello = true;
            }
        }

        // todo nonce
        // todo bye

        // send encrypted response
        byte[] encryptedReplyToHello = EncryptDecryptHelper.encryptString(AuthenticationConstants.SERVER_REPLY_TO_HELLO, this.encryptCipher);
        serverSocket.sendByteArrayForClient(0, encryptedReplyToHello);

    }



    private void waitForClientToAskForCertificate() throws IOException {
        System.out.println("Waiting for client to ask for certificate...");
        // wait for client to ask for certificate
        boolean clientAskedForCertificate = false;

        while (!clientAskedForCertificate) {

            String clientMessage = this.serverSocket.readMessageLineForClient(0);

            if (clientMessage.equals(AuthenticationConstants.CLIENT_ASK_FOR_CERT)) {
                clientAskedForCertificate = true;
            }
        }

        // send certificate
        byte[] serverCert = SecurityFileReader.readFileIntoByteArray(FilePaths.SERVER_CERTIFICATE);
        serverSocket.sendByteArrayForClient(0, serverCert);

    }


    private void waitForClientToSendSymmetricKey() throws IOException {
        // todo by pablo
        System.out.println("Waiting for client to send symmetric key...");
        // wait for client to sent symmetric key
        byte[] receivedEncryptedSymmetricKey = this.serverSocket.readByteArrayForClient(0);

    }

    private void waitForClientToSendFile() {

        // todo by pablo

        System.out.println("Waiting for client to send file...");
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        AwesomeFileTransferServer server = new AwesomeFileTransferServer();
        server.start();

    }

}
