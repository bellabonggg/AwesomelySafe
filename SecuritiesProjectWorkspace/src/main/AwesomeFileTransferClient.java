package main;

import AwesomeSockets.AwesomeClientSocket;
import constants.AuthenticationConstants;
import encryption.*;
import constants.FilePaths;
import tests.TestOfAwesomeness;

import javax.crypto.*;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
    private Key serverPublicKey;
    public AwesomeFileTransferClient(int port, String pathOfFileToSend, int fileTransferProtocol) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.clientSocket = new AwesomeClientSocket(AuthenticationConstants.SERVER_IP, port);
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

        if (fileTransferProtocol == 1) {

            sendToServerFileUploadRSA();

        } else {

            // DES

            sendToServerSymmetricKey();
            sendToServerFileUpload();

        }

        System.out.println("File Sent");

    }

    private void sendHelloToServer() throws IOException, IllegalAccessException, NoSuchAlgorithmException {

        System.out.println("Sending hello to server...");

        // get a nonce for this message
        this.helloNonce = NonceHelper.getNonce();

        byte[] concatenatedMessageWithNonce = ByteArrayHelper.concatenateBytes(this.helloNonce, AuthenticationConstants.CLIENT_HELLO_MESSAGE.getBytes());

        // message = helloNonce + ClientHelloMessage

        this.clientSocket.sendByteArray(concatenatedMessageWithNonce);

        // read and store message. Cannot verify yet as we don't have the public key
        this.serverHelloMessage = this.clientSocket.readByteArray();
    }

    private void askServerForCertificate() throws IOException, CertificateException, IllegalAccessException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Asking server for certificate...");

        // get a nonce for this message
        this.askForCertNonce = NonceHelper.getNonce();

        // message = askForCertNonce + ClientAskForCertificate
        byte[] askForCertMessageWithNonce = ByteArrayHelper.concatenateBytes(this.askForCertNonce, AuthenticationConstants.CLIENT_ASK_FOR_CERT.getBytes());
        this.clientSocket.sendByteArray(askForCertMessageWithNonce);

        // gets and splits the received messsage
        byte[] receivedMessage = this.clientSocket.readByteArray();
        byte[][] splitMessage = ByteArrayHelper.splitMessage(receivedMessage, EncryptDecryptHelper.BLOCK_LENGTH_AFTER_RSA);

        // Encrypted nonce received
        byte[] encryptedAskForCertNonce = splitMessage[0];

        // Server Certificate
        byte[] receivedCertificate = splitMessage[1];




        X509Certificate serverCert = this.verifyServerAndGetCertificate(receivedCertificate);

        if (serverCert == null ) {
            throw new IllegalAccessException("Certificate is invalid");
        }

        System.out.println("Server certificate is verified.");

        // gets the public key from the certificate
        serverPublicKey = serverCert.getPublicKey();

        // sets up a decrypting cipher using the public key
        Cipher decryptCipher = EncryptDecryptHelper.getDecryptCipher(serverPublicKey, AuthenticationConstants.ALGORITHM_RSA);
        encryptCipher = EncryptDecryptHelper.getEncryptCipher(serverPublicKey, AuthenticationConstants.ALGORITHM_RSA);

        // verifies the previously stored server respond to the hello

        // decrypts the message
        byte[] serverDecryptedHelloWithNonce = EncryptDecryptHelper.decryptBytes(this.serverHelloMessage, decryptCipher);

        // splits the message
        byte[][] splitServerHelloWithNonce = ByteArrayHelper.splitMessage(serverDecryptedHelloWithNonce, NonceHelper.NONCE_LENGTH);

        byte[] receivedAskForCertNonce = splitServerHelloWithNonce[0];
        byte[] receivedServerHelloBytes = splitServerHelloWithNonce[1];

        String serverDecryptedMessage = new String(receivedServerHelloBytes);

        // Check to see if the previously received server reply to hello is expected
        boolean verifyServerHello = serverDecryptedMessage.equals(AuthenticationConstants.SERVER_REPLY_TO_HELLO);

        // Check to see if the previously received server reply to hello nonce is valid
        boolean verifyServerHelloNonce = NonceHelper.verifyNonces(this.helloNonce, receivedAskForCertNonce);

        // decrypt the previously received askForCertNonce
        byte[] decryptedAskForCertNonce = EncryptDecryptHelper.decryptBytes(encryptedAskForCertNonce, decryptCipher);

        // verify the ask for cert nonce that is now decrypted
        boolean verifyAskForCertNonce = NonceHelper.verifyNonces(this.askForCertNonce, decryptedAskForCertNonce);


        // small method that can be simplified using boolean algebra, but we want to print the verification that fails
        boolean[] checks = new boolean[]{verifyServerHello, verifyServerHelloNonce, verifyAskForCertNonce};
        boolean checksSucceeded = true;
        for (int i = 0; i < checks.length; i++) {
            boolean check = checks[i];
            if (!check) {
                checksSucceeded = false;
                System.err.println("Check " + i + " failed.");
            }
        }

        // throws an exception if any checks have failed
        if (!checksSucceeded) {
            throw new IllegalAccessException("Cannot verify server hello message!");
        }

    }

    /**
     *
     * @param receivedCertificate
     * @return null if certificate cannot be verified
     * @throws FileNotFoundException
     * @throws CertificateException
     */
    private X509Certificate verifyServerAndGetCertificate(byte[] receivedCertificate) throws FileNotFoundException, CertificateException {
        // verify certificate
        X509Certificate serverCert = X509Certificate.getInstance(receivedCertificate);
        InputStream caCertInputStream = new FileInputStream(FilePaths.CA_CERTIFICATE);
        X509Certificate caCert = X509Certificate.getInstance(caCertInputStream);

        if (!CertificateVerifier.verifyCertificate(caCert, serverCert)) {
            return null;
        }

        return serverCert;

    }


    private void sendToServerSymmetricKey() throws NoSuchAlgorithmException, IOException {
        System.out.println("Sending symmetric key to server");
        this.key = KeyGenerator.getInstance(SecurityFileReader.AES_KEY).generateKey();
        byte[] data = key.getEncoded();
        System.out.println("client symm key length: " + data.length);
        System.out.println(Arrays.toString(data));
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
    	Cipher secretEncryptCipher = EncryptDecryptHelper.getEncryptCipher(this.key, AuthenticationConstants.ALGORITHM_AES);
    	byte [] encryptedFile = secretEncryptCipher.doFinal(this.fileToSend);
    	//send to server
    	this.clientSocket.sendByteArray(encryptedFile);
    }

    private void sendToServerFileUploadRSA() throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        //read file, change filepath
        this.fileToSend = SecurityFileReader.readFileIntoByteArray(this.pathOfFileToSend);


        //encrypt file with symmetrickey
        Cipher secretEncryptCipher = EncryptDecryptHelper.getEncryptCipher(this.serverPublicKey, AuthenticationConstants.ALGORITHM_RSA);
        byte [] encryptedFile = EncryptDecryptHelper.encryptByte(this.fileToSend,this.encryptCipher);
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
        AwesomeFileTransferClient client = new AwesomeFileTransferClient(AuthenticationConstants.PORT, TestOfAwesomeness.BIG_IMAGE_PATH, 1);
        client.start();
        System.out.println("File to send: " + Arrays.toString(client.getFileToSend()));
    }
}
