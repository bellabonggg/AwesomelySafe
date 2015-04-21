package main;


import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import AwesomeSockets.AwesomeServerSocket;
import constants.AuthenticationConstants;
import constants.FilePaths;
import encryption.EncryptDecryptHelper;
import encryption.SecurityFileReader;

/**
 * Created by JiaHao on 19/4/15.
 */
public class AwesomeFileTransferServer {

    private final AwesomeServerSocket serverSocket;
    private final Cipher encryptCipher;
    private final Cipher  decryptCipher;
    private Cipher symmetricCipher;
    

    public AwesomeFileTransferServer() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.serverSocket = new AwesomeServerSocket(AuthenticationConstants.PORT);
        this.encryptCipher = EncryptDecryptHelper.getEncryptCipher(FilePaths.SERVER_PRIVATE_KEY, AuthenticationConstants.ALGORITHM_RSA, 0);

        this.decryptCipher = EncryptDecryptHelper.getDecryptCipher(FilePaths.SERVER_PRIVATE_KEY, AuthenticationConstants.ALGORITHM_RSA, 0);

//        this.symmetricCipher = Cipher.getInstance(AuthenticationConstants.ALGORITHM_DES);

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
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
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


    private void waitForClientToSendSymmetricKey() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {

        System.out.println("Waiting for client to send symmetric key...");
        // wait for client to sent symmetric key
        byte[] receivedEncryptedSymmetricKey = this.serverSocket.readByteArrayForClient(0);
        byte[] receivedDecryptedSymmetricKey = EncryptDecryptHelper.decryptBytes(receivedEncryptedSymmetricKey, this.decryptCipher);
        Key symmetricKey = new SecretKeySpec(receivedDecryptedSymmetricKey, 0, receivedDecryptedSymmetricKey.length, "DES");

//        this.symmetricCipher.init(Cipher.DECRYPT_MODE, key2);

        this.symmetricCipher = EncryptDecryptHelper.getDecryptCipher(symmetricKey, AuthenticationConstants.ALGORITHM_DES);
    }

    private void waitForClientToSendFile() throws IOException {
    	System.out.println("Waiting for client to send file...");
    	byte [] finalRawData =  this.serverSocket.readByteArrayForClient(0);
    	byte [] finalDecryptedData = EncryptDecryptHelper.decryptBytes(finalRawData,symmetricCipher);

        System.out.println("Final decrypted: " + Arrays.toString(finalDecryptedData));
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        AwesomeFileTransferServer server = new AwesomeFileTransferServer();
        server.start();

    }

}
