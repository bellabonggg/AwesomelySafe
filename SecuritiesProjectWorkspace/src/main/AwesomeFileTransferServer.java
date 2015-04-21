package main;


import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import AwesomeSockets.AwesomeServerSocket;
import constants.AuthenticationConstants;
import constants.FilePaths;
import encryption.EncryptDecryptHelper;
import encryption.NonceHelper;
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

    }

    public void start() throws IOException, BadPaddingException, IllegalBlockSizeException {
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
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    public void confidentialityProtocol() throws BadPaddingException, IllegalBlockSizeException {
        System.out.println("=== CONFIDENTIALITY PROTOCOL ===");

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


    private void waitForClientToSayHello() throws IOException, IllegalAccessException {
        System.out.println("Waiting for client to say hello...");
        String errorMessage = "Client sent unknown hello message";

        dealWithMessage(AuthenticationConstants.CLIENT_HELLO_MESSAGE, AuthenticationConstants.SERVER_REPLY_TO_HELLO.getBytes(), errorMessage, true);

    }

    private void waitForClientToAskForCertificate() throws IOException, IllegalAccessException {
        System.out.println("Waiting for client to ask for certificate...");
        // wait for client to ask for certificate

        String errorMessage = "Client sent unknown ask for certificate message";
        byte[] serverCert = SecurityFileReader.readFileIntoByteArray(FilePaths.SERVER_CERTIFICATE);

        dealWithMessage(AuthenticationConstants.CLIENT_ASK_FOR_CERT, serverCert, errorMessage, false);

    }

    private void dealWithMessage(String stringCheck, byte[] replyMessage, String errorMessage, boolean encryptResponse) throws IllegalAccessException, IOException {

        byte[] receivedClientHelloWithNonce = this.serverSocket.readByteArrayForClient(0);
        byte[][] splitClientHelloWithNonce = ByteArrayHelper.splitMessage(receivedClientHelloWithNonce, NonceHelper.NONCE_LENGTH);

        byte[] clientHelloNonce = splitClientHelloWithNonce[0];
        String clientHelloMessage = new String(splitClientHelloWithNonce[1]);

        if (!clientHelloMessage.equals(stringCheck)) {
            throw new IllegalAccessException(errorMessage);
        }

        byte[] messageToSend;
        if (encryptResponse) {

            byte[] nonceWithReplyMessage = ByteArrayHelper.concatenateBytes(clientHelloNonce, replyMessage);
            messageToSend = EncryptDecryptHelper.encryptByte(nonceWithReplyMessage, this.encryptCipher);
        } else {
            byte[] encryptedNonce = EncryptDecryptHelper.encryptByte(clientHelloNonce, this.encryptCipher);
            messageToSend = ByteArrayHelper.concatenateBytes(encryptedNonce, replyMessage);
        }

        serverSocket.sendByteArrayForClient(0, messageToSend);

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

    private void waitForClientToSendFile() throws IOException, BadPaddingException, IllegalBlockSizeException {
    	System.out.println("Waiting for client to send file...");
    	byte [] finalRawData =  this.serverSocket.readByteArrayForClient(0);
    	byte [] finalDecryptedData = symmetricCipher.doFinal(finalRawData);

        System.out.println("Final decrypted: " + Arrays.toString(finalDecryptedData));
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        AwesomeFileTransferServer server = new AwesomeFileTransferServer();
        server.start();

    }

}
