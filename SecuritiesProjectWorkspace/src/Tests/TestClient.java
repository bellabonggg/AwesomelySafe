package Tests;

import AwesomeSockets.AwesomeClientSocket;
import authentication.AuthenticationConstants;
import encryption.EncryptDecryptHelper;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by JiaHao on 20/4/15.
 */
public class TestClient {

    private byte[] rawBytes;

    public TestClient() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        AwesomeClientSocket awesomeClientSocket = new AwesomeClientSocket(AuthenticationConstants.SERVER_IP, AuthenticationConstants.PORT);




        File file = new File(TestEncryptDecrypt.BIG_FILE_PATH);

        FileInputStream fileInputStream = new FileInputStream(file);

        this.rawBytes = new byte[(int) file.length()];
        fileInputStream.read(rawBytes);

//        System.out.println(Arrays.toString(rawBytes));
        byte[] encryptString = EncryptDecryptHelper.encryptByte(rawBytes, TestEncryptDecrypt.getEncryptCipher());

//        System.out.println(encryptString);

        awesomeClientSocket.sendByteArray(encryptString);

    }

    public byte[] getRawBytes() {
        return rawBytes;
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        TestClient client = new TestClient();
    }
}
