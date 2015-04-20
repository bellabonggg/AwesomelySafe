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

    /**
     * Test encryption on small string
     * @throws IOException
     */
    public void testEncryptDecryptString() throws IOException {

        String message = "Hello";


        byte[] encryptString = EncryptDecryptHelper.encryptString(message);
        System.out.println(Arrays.toString(message.getBytes()));


        String decryptedMessage = EncryptDecryptHelper.decryptMessage(encryptString);

        System.out.println(Arrays.toString(decryptedMessage.getBytes()));
        assertTrue(message.equals(decryptedMessage));
    }

    /**
     * Test encryption on a small file
     * @throws IOException
     */
    public void testEncryptDecryptSmallBytes() throws IOException {


        testEncryptDecryptFile("src/Keys/testFile.txt");

    }

    /**
     * Test encryption on a file size > 117 bytes
     * @throws IOException
     */
    public void testEncryptDecryptBigBytes() throws IOException {

        testEncryptDecryptFile("src/Keys/testFileBig.txt");

    }

    /**
     * Tests encryption over sockets
     * @throws InterruptedException
     */
    public void testServerClient() throws InterruptedException {

        final byte[][] results = new byte[2][];

        Thread serverThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    TestServer server = new TestServer();
                    results[1] = server.getDecryptedBytes();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        });


        Thread clientThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    TestClient client = new TestClient();
                    results[0] = client.getRawBytes();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        serverThread.start();
        clientThread.start();

        serverThread.join();
        clientThread.join();

        assertTrue(Arrays.equals(results[0], results[1]));

    }

    /**
     * Helper test method for encryption of a file path
     * @param path
     * @throws IOException
     */
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

