package Tests;

import encryption.EncryptDecryptHelper;
import junit.framework.TestCase;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by JiaHao on 19/4/15.
 */
public class TestEncryptDecrypt extends TestCase {

    public static final String BIG_FILE_PATH = "src/Keys/testFileBig.txt";
    public static final String SMALL_FILE_PATH = "src/Keys/testFile.txt";

    /**
     * Test encryption on small string
     * @throws IOException
     */
    public void testEncryptDecryptString() throws IOException {

        String message = "Hello";
        
        byte[] encryptString = EncryptDecryptHelper.encryptString(message);
        String decryptedMessage = EncryptDecryptHelper.decryptMessage(encryptString);

        assertTrue(message.equals(decryptedMessage));
    }

    /**
     * Test encryption on a small file
     * @throws IOException
     */
    public void testEncryptDecryptSmallBytes() throws IOException {

        testEncryptDecryptFile(SMALL_FILE_PATH);

    }

    /**
     * Test encryption on a file size > 117 bytes
     * @throws IOException
     */
    public void testEncryptDecryptBigBytes() throws IOException {

        testEncryptDecryptFile(BIG_FILE_PATH);

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



        assertTrue(Arrays.equals(rawBytes, decryptedBytes));


    }

}

