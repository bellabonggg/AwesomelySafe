package authentication;

/**
 * Created by JiaHao on 19/4/15.
 */
public class AuthenticationConstants {
    public static String CLIENT_HELLO_MESSAGE = "Hello SecStore, please prove your identity!";
    public static String SERVER_REPLY_TO_HELLO = "Hello, this is SecStore";

    public static String CLIENT_ASK_FOR_CERT = "Give me your certificate signed by CA";

    public static String BYE = "bye";


    public static int PORT = 5432;

    public static String SERVER_IP = "127.0.0.1";


    public static String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
}
