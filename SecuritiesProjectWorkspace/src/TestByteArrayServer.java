import AwesomeSockets.AwesomeServerSocket;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by JiaHao on 17/4/15.
 */
public class TestByteArrayServer {


    public static void main(String[] args) throws IOException {

        AwesomeServerSocket serverSocket = new AwesomeServerSocket(5555);

        serverSocket.acceptClient();
        byte[] readMessage = serverSocket.readByteArrayForClient(0);


        System.out.println(Arrays.toString(readMessage));

    }


}
