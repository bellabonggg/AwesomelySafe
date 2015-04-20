package authentication;

import AwesomeSockets.AwesomeClientSocket;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by JiaHao on 20/4/15.
 */
public class TestClient {

    private byte[] rawBytes;

    public TestClient() throws IOException {

        AwesomeClientSocket awesomeClientSocket = new AwesomeClientSocket("127.0.0.1", 5321);




        File file = new File("src/Keys/testFileBig.txt");

        FileInputStream fileInputStream = new FileInputStream(file);

        this.rawBytes = new byte[(int) file.length()];
        fileInputStream.read(rawBytes);

        System.out.println(Arrays.toString(rawBytes));
        byte[] encryptString = EncryptDecryptHelper.encryptByte(rawBytes);

        System.out.println(encryptString);

        awesomeClientSocket.sendByteArray(encryptString);



    }

    public byte[] getRawBytes() {
        return rawBytes;
    }

    public static void main(String[] args) throws IOException {

        TestClient client = new TestClient();
    }
}
