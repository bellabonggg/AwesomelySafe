package authentication;

import junit.framework.TestCase;

import java.io.IOException;

/**
 * Created by JiaHao on 19/4/15.
 */
public class TestEncryptDecrypt extends TestCase {

    public void testEncryptDecrypt() throws IOException {
        String message = "hello";

        byte[] encryptString = APServer.encryptString(message);


        String decryptedMessage = APServer.decryptMessage(encryptString);

        assertTrue(message.equals(decryptedMessage));
    }



}
