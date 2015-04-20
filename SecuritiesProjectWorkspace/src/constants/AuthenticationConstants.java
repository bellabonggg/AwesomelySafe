package constants;

/**
 * Created by JiaHao on 19/4/15.
 */
public class AuthenticationConstants {
    public static final String CLIENT_HELLO_MESSAGE = "Hello SecStore, please prove your identity!";
    public static final String SERVER_REPLY_TO_HELLO = "Hello, this is SecStore";

    public static final String CLIENT_ASK_FOR_CERT = "Give me your certificate signed by CA";

    public static final String BYE = "bye";


    public static final int PORT = 5432;

    public static final String SERVER_IP = "127.0.0.1";


    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";


}
