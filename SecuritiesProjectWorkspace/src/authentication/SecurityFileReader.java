package authentication;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.*;
import java.util.Arrays;

/**
 * Created by JiaHao on 19/4/15.
 */
public class SecurityFileReader {


    /**
     *
     * @param path sample "src/CA.crt"
     * @return
     * @throws IOException
     */
    public static byte[] readFileIntoByteArray(String path) throws IOException {
        File file = new File(path);

        FileInputStream fileInputStream = new FileInputStream(file);

        byte[] dataByte = new byte[(int)file.length()];
        fileInputStream.read(dataByte);

        return dataByte;
    }


    /**
     *
     * @param path
     * @param privateOrPublic 0 if private, 1 if public
     * @return null if exception caught
     * @throws IOException
     */
    public static Key readFileIntoKey(String path, int privateOrPublic) throws IOException {
        byte[] keyBytes = readFileIntoByteArray(path);


        EncodedKeySpec keySpec;

        if (privateOrPublic == 0) {
            keySpec = new PKCS8EncodedKeySpec(keyBytes);

        } else {
            keySpec = new X509EncodedKeySpec(keyBytes);
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            Key key;

            if (privateOrPublic == 0) {
                key = keyFactory.generatePrivate(keySpec);
            } else {
                key = keyFactory.generatePublic(keySpec);
            }

            return key;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("Wrong privateOrPublic argument entered");
        }

        return null;
    }

    public static void main(String[] args) throws IOException {

        Key myKey = readFileIntoKey("src/Keys/privateServer.der", 0);
        System.out.println(Arrays.toString(myKey.getEncoded()));

    }
}
