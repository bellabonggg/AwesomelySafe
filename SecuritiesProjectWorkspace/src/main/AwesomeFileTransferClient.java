package main;

import AwesomeSockets.AwesomeClientSocket;
import constants.AuthenticationConstants;
import encryption.*;
import constants.FilePaths;
import tests.TestEncryptDecrypt;

import javax.crypto.*;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by JiaHao on 19/4/15.
 */
public class AwesomeFileTransferClient {

    private final AwesomeClientSocket clientSocket;
    private final String pathOfFileToSend;
    private final int fileTransferProtocol;

    private Cipher encryptCipher;
    private byte[] serverHelloMessage;
    private SecretKey key;
    private byte[] helloNonce;
    private byte[] askForCertNonce;

    private byte[] fileToSend;

    public AwesomeFileTransferClient(String pathOfFileToSend, int fileTransferProtocol) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.clientSocket = new AwesomeClientSocket(AuthenticationConstants.SERVER_IP, AuthenticationConstants.PORT);
        this.pathOfFileToSend = pathOfFileToSend;
        this.fileTransferProtocol = fileTransferProtocol;
    }



    public void start() throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        authenticationProtocol();
        confidentialityProtocol();
    }

    public void authenticationProtocol() throws IOException {
        System.out.println("=== AUTHENTICATION PROTOCOL ===");

        //todo error catching
        try {
            sendHelloToServer();
            askServerForCertificate();

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

    private void confidentialityProtocol() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("=== CONFIDENTIALITY PROTOCOL ===");

        if (fileTransferProtocol == 0) {

            // DES

            sendToServerSymmetricKey();
            sendToServerFileUpload();

        } else {

            // TODO RSA

        }

    }

    private void sendHelloToServer() throws IOException, IllegalAccessException, NoSuchAlgorithmException {

        System.out.println("Sending hello to server...");


//        this.sendHashedMessageWithNonce(AuthenticationConstants.CLIENT_HELLO_MESSAGE.getBytes());

//        this.clientSocket.sendMessageLine(AuthenticationConstants.CLIENT_HELLO_MESSAGE);

        this.helloNonce = NonceHelper.getNonce();
        byte[] concatenatedMessageWithNonce = ByteArrayHelper.concatenateBytes(this.helloNonce, AuthenticationConstants.CLIENT_HELLO_MESSAGE.getBytes());

        this.clientSocket.sendByteArray(concatenatedMessageWithNonce);

        this.serverHelloMessage = this.clientSocket.readByteArray();
    }

    private void askServerForCertificate() throws IOException, CertificateException, IllegalAccessException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        // todo nonce
        System.out.println("Asking server for certificate...");

        this.askForCertNonce = NonceHelper.getNonce();

        byte[] askForCertMessageWithNonce = ByteArrayHelper.concatenateBytes(this.askForCertNonce, AuthenticationConstants.CLIENT_ASK_FOR_CERT.getBytes());

        this.clientSocket.sendByteArray(askForCertMessageWithNonce);


        byte[] receivedMessage = this.clientSocket.readByteArray();
        byte[][] splitMessage = ByteArrayHelper.splitMessage(receivedMessage, EncryptDecryptHelper.BLOCK_LENGTH_AFTER_RSA);


        byte[] encryptedAskForCertNonce = splitMessage[0];
        byte[] receivedCertificate = splitMessage[1];


        X509Certificate serverCert = X509Certificate.getInstance(receivedCertificate);
        InputStream caCertInputStream = new FileInputStream(FilePaths.CA_CERTIFICATE);
        X509Certificate caCert = X509Certificate.getInstance(caCertInputStream);

        if (!CertificateVerifier.verifyCertificate(caCert, serverCert)) {
            throw new IllegalAccessException("Cannot verify certificate");
        } else {
            System.out.println("Server certificate is verified.");


            Key serverPublicKey = serverCert.getPublicKey();

            Cipher decryptCipher = EncryptDecryptHelper.getDecryptCipher(serverPublicKey, AuthenticationConstants.ALGORITHM_RSA);
            encryptCipher = EncryptDecryptHelper.getEncryptCipher(serverPublicKey, AuthenticationConstants.ALGORITHM_RSA);

            byte[] serverDecryptedHelloWithNonce = EncryptDecryptHelper.decryptBytes(this.serverHelloMessage, decryptCipher);

            byte[][] splitServerHelloWithNonce = ByteArrayHelper.splitMessage(serverDecryptedHelloWithNonce, NonceHelper.NONCE_LENGTH);

            byte[] receivedAskForCertNonce = splitServerHelloWithNonce[0];
            byte[] receivedServerHelloBytes = splitServerHelloWithNonce[1];

            String serverDecryptedMessage = new String(receivedServerHelloBytes);

            // check if the server reply to hello is correct

            // decrypt askForCertNonce
            byte[] decryptedAskForCertNonce = EncryptDecryptHelper.decryptBytes(encryptedAskForCertNonce, decryptCipher);


            boolean verifyServerHello = serverDecryptedMessage.equals(AuthenticationConstants.SERVER_REPLY_TO_HELLO);
            boolean verifyServerHelloNonce = NonceHelper.verifyNonces(this.helloNonce, receivedAskForCertNonce);
            boolean verifyAskForCertNonce = NonceHelper.verifyNonces(this.askForCertNonce, decryptedAskForCertNonce);

            boolean[] checks = new boolean[]{verifyServerHello, verifyServerHelloNonce, verifyAskForCertNonce};

            boolean checksSucceeded = true;

            for (int i = 0; i < checks.length; i++) {
                boolean check = checks[i];
                if (!check) {
                    checksSucceeded = false;
                    System.err.println("Check " + i + " failed.");

                }
            }

            if (!checksSucceeded) {
                throw new IllegalAccessException("Cannot verify server hello message!");
            }
        }
    }


    private void sendToServerSymmetricKey() throws NoSuchAlgorithmException, IOException {
        System.out.println("Sending symmetric key to server");
        this.key = KeyGenerator.getInstance("DES").generateKey();
        byte[] data = key.getEncoded();
        byte [] encryptedKey = encryptSymmetricKey(data);
        clientSocket.sendByteArray(encryptedKey);
        
    }
    private byte[] encryptSymmetricKey(byte[] key) throws IOException{
    	byte[] encryptedKey = EncryptDecryptHelper.encryptByte(key, encryptCipher);
    	return encryptedKey;
    }

    private void sendToServerFileUpload() throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    	//read file, change filepath
    	this.fileToSend = SecurityFileReader.readFileIntoByteArray(this.pathOfFileToSend);


    	//encrypt file with symmetrickey
    	Cipher secretEncryptCipher = EncryptDecryptHelper.getEncryptCipher(this.key, AuthenticationConstants.ALGORITHM_DES);
    	byte [] encryptedFile = secretEncryptCipher.doFinal(this.fileToSend);
    	//send to server
    	this.clientSocket.sendByteArray(encryptedFile);
    }
    
    private void closeClient() throws IOException {

        this.clientSocket.sendMessageLine(AuthenticationConstants.BYE);
        this.clientSocket.closeClient();

    }

    public byte[] getFileToSend() {
        return fileToSend;
    }

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, IllegalBlockSizeException {
        AwesomeFileTransferClient client = new AwesomeFileTransferClient(TestEncryptDecrypt.BIG_FILE_PATH, 0);
        client.start();
        System.out.println("File to send: " + Arrays.toString(client.getFileToSend()));
    }
}
