package encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by JiaHao on 21/4/15.
 */
public class MD5Helper {
    public static final int MD5_LENGTH = 128;

    private static String MD5_ALGORITHM = "MD5";

    public static byte[] getMd5(byte[] message) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance(MD5_ALGORITHM);
        return md.digest(message);

    }


}
