package authentication;


import AwesomeSockets.AwesomeServerSocket;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by JiaHao on 19/4/15.
 */
public class APServer {

    private final AwesomeServerSocket serverSocket;
    private int state;



    public APServer() throws IOException {
        this.serverSocket = new AwesomeServerSocket(AuthenticationConstants.PORT);


        this.state = 0;

    }


    public void start() throws IOException {
        nextState();

    }

    public void nextState() {

        try {

            if (state == 0) {
                acceptClient();

            } else if (state == 1) {
                waitForClientToSayHello();
            } else if (state == 2) {
                waitForClientToAskForCertificate();
            } else if (state == 3) {
                waitForClientToSendSymmetricKey();
            }

            // if exception is caught, do not proceed to next state
            state++;

        } catch (IOException e) {

            e.printStackTrace();

        }

    }

    private void acceptClient() throws IOException {

        this.serverSocket.acceptClient();

        this.nextState();

    }

    private void waitForClientToSayHello() throws IOException {

        // wait for client to say hello
        boolean clientSaidHello = false;

        while (!clientSaidHello) {

            String clientMessage = this.serverSocket.readMessageLineForClient(0);

            if (clientMessage.equals(AuthenticationConstants.CLIENT_HELLO_MESSAGE)) {
                clientSaidHello = true;
            }
        }


        // send encrypted response
        byte[] encryptedReplyToHello = encryptString(AuthenticationConstants.SERVER_REPLY_TO_HELLO);
        serverSocket.sendByteArrayForClient(0, encryptedReplyToHello);


        // nextState
        this.nextState();

    }

    private void waitForClientToAskForCertificate()  {


        // wait for client to ask for certificate

        // send certificate

        // nextState
        this.nextState();

    }


    private void waitForClientToSendSymmetricKey() {


        // wait for client to sent symmetric key


        // next state
        this.nextState();

    }

    public static byte[] encryptString(String message) throws IOException {

        Key privateKey = SecurityFileReader.readFileIntoKey(FilePaths.SERVER_PRIVATE_KEY, 0);

        try {
            Cipher cipher = Cipher.getInstance(AuthenticationConstants.CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);


            return cipher.doFinal(message.getBytes());

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }


        return null;
    }

    public static String decryptMessage(byte[] message) throws IOException {


        Key publicKey = SecurityFileReader.readFileIntoKey(FilePaths.SERVER_PUBLIC_KEY, 1);

        try {
            Cipher cipher = Cipher.getInstance(AuthenticationConstants.CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);


            byte[] decryptedBytes = cipher.doFinal(message);

            return new String(decryptedBytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }


        return null;
    }




    public static void main(String[] args) throws IOException {




    }

}
