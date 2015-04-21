package encryption;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by JiaHao on 21/4/15.
 */
public class NonceHelper {

    public static final int NONCE_LENGTH = 4;
    /**
     * Get a nonce of length 4
     * @return
     */
    public static byte[] getNonce() {
        SecureRandom random = new SecureRandom();
        int randomNumber = random.nextInt();

        return ByteBuffer.allocate(NONCE_LENGTH).putInt(randomNumber).array();
    }

    public static boolean verifyNonces(byte[] reference, byte[] nonceToCheck) {
        return Arrays.equals(reference, nonceToCheck);
    }
}
