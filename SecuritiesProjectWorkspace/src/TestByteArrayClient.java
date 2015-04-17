import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by JiaHao on 17/4/15.
 */
public class TestByteArrayClient {


    public static void main(String[] args) throws IOException {

        AwesomeClientSocket clientSocket = new AwesomeClientSocket("localhost", 5555);


        File file = new File("src/CA.crt");


        FileInputStream fileInputStream = new FileInputStream(file);

        byte[] dataByte = new byte[(int)file.length()];
        fileInputStream.read(dataByte);
        System.out.println(Arrays.toString(dataByte));
        clientSocket.sendByteArray(dataByte);


    }
}
