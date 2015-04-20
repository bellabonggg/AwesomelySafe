package authentication;

import junit.framework.TestCase;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by JiaHao on 19/4/15.
 */
public class TestEncryptDecrypt extends TestCase {

    public void testEncryptDecryptString() throws IOException {

        String message = "Hello";


        byte[] encryptString = EncryptDecryptHelper.encryptString(message);
        System.out.println(Arrays.toString(message.getBytes()));


        String decryptedMessage = EncryptDecryptHelper.decryptMessage(encryptString);

        System.out.println(Arrays.toString(decryptedMessage.getBytes()));
        assertTrue(message.equals(decryptedMessage));
    }

    public void testEncryptDecryptSmallBytes() throws IOException {


        testEncryptDecryptFile("src/Keys/testFile.txt");

    }

    public void testEncryptDecryptBigBytes() throws IOException {

        testEncryptDecryptFile("src/Keys/testFileBig.txt");

    }


    public void testServerClient() {

        Thread serverThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    TestServer server = new TestServer();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        });


        Thread clientThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    TestClient server = new TestClient();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

    }

    public static void testEncryptDecryptFile(String path) throws IOException {
        File file = new File(path);

        FileInputStream fileInputStream = new FileInputStream(file);

        byte[] rawBytes = new byte[(int) file.length()];
        fileInputStream.read(rawBytes);

        byte[] encryptString = EncryptDecryptHelper.encryptByte(rawBytes);

        byte[] decryptedBytes = EncryptDecryptHelper.decryptBytes(encryptString);

        String decryptString = EncryptDecryptHelper.decryptMessage(encryptString);
        System.out.println(decryptString);
        assertTrue(Arrays.equals(rawBytes, decryptedBytes));


    }

}

