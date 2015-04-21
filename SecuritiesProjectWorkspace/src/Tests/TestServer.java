package tests;

import AwesomeSockets.AwesomeServerSocket;
import constants.AuthenticationConstants;
import encryption.EncryptDecryptHelper;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by JiaHao on 20/4/15.
 */
public class TestServer {

    private byte[] decryptedMessage;

    public TestServer() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        AwesomeServerSocket serverSocket = new AwesomeServerSocket(AuthenticationConstants.PORT);

        serverSocket.acceptClient();
        byte[] receivedMessage = serverSocket.readByteArrayForClient(0);


        this.decryptedMessage = EncryptDecryptHelper.decryptBytes(receivedMessage, TestOfAwesomeness.getDecryptCipher());


    }


    public byte[] getDecryptedBytes() {

        return this.decryptedMessage;

    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        TestServer server = new TestServer();
        System.out.println(Arrays.toString(server.getDecryptedBytes()));

    }
}
