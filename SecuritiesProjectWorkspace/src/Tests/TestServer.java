package Tests;

import AwesomeSockets.AwesomeServerSocket;
import authentication.AuthenticationConstants;
import encryption.EncryptDecryptHelper;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by JiaHao on 20/4/15.
 */
public class TestServer {

    private byte[] decryptedMessage;

    public TestServer() throws IOException {

        AwesomeServerSocket serverSocket = new AwesomeServerSocket(AuthenticationConstants.PORT);

        serverSocket.acceptClient();
        byte[] receivedMessage = serverSocket.readByteArrayForClient(0);


        this.decryptedMessage = EncryptDecryptHelper.decryptBytes(receivedMessage);


    }


    public byte[] getDecryptedBytes() {

        return this.decryptedMessage;

    }

    public static void main(String[] args) throws IOException {

        TestServer server = new TestServer();
        System.out.println(Arrays.toString(server.getDecryptedBytes()));

    }
}
