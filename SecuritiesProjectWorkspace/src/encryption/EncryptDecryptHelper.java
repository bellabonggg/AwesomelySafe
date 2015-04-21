package encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by JiaHao on 20/4/15.
 */
public class EncryptDecryptHelper {

    public static final int BLOCK_LENGTH_BEFORE_RSA = 117;
    public static final int BLOCK_LENGTH_AFTER_RSA = 128;

    /**
     * Encrypts a string to a byte[]
     * @throws IOException
     */
    public static byte[] encryptString(String message, Cipher cipher) throws IOException {

        return encryptByte(message.getBytes(), cipher);
    }


    /**
     * Encrypts raw bytes
     * @param rawBytes
     * @return null if error
     * @throws IOException
     */
    public static byte[] encryptByte(byte[] rawBytes, Cipher cipher) throws IOException {

        int rawBytesLength = rawBytes.length;
//        System.out.println("Starting byte length: " + rawBytesLength);

        try {

//            byte[] latestBlock = new byte[AuthenticationConstants.BLOCK_LENGTH_BEFORE_RSA];
            List<byte[]> blocks = spitByteArray(rawBytes, BLOCK_LENGTH_BEFORE_RSA);


            return cipherAndCombine(blocks, cipher, BLOCK_LENGTH_AFTER_RSA);

        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }


        return null;
    }

    /**
     * Decrypts raw bytes
     * @param rawBytes
     * @return null if error decrypting
     * @throws IOException
     */
    public static byte[] decryptBytes(byte[] rawBytes, Cipher cipher) throws IOException {

        try {



            List<byte[]> blocks = spitByteArray(rawBytes, BLOCK_LENGTH_AFTER_RSA);

//            byte[] decryptedBytes = cipher.doFinal(rawBytes);

            byte[] decryptedCombinedWithZeroes = cipherAndCombine(blocks, cipher, BLOCK_LENGTH_BEFORE_RSA);

            int lastValidIndex = 0;
            for (int i = decryptedCombinedWithZeroes.length - 1; i >= 0; i--) {

                if (decryptedCombinedWithZeroes[i] != 0) {
                    lastValidIndex = i;
                    break;
                }

            }

            byte[] finalDecrypted = new byte[lastValidIndex + 1];
            for (int i = 0; i <= lastValidIndex; i++) {

                finalDecrypted[i] = decryptedCombinedWithZeroes[i];

            }


            return finalDecrypted;

        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }


        return null;
    }


    /**
     * Decrypts raw bytes into a string
     * @param message
     * @return null if error decrypting
     * @throws IOException
     */
    public static String decryptMessage(byte[] message, Cipher cipher) throws IOException {

        return new String(decryptBytes(message, cipher));

    }

    /**
     * Helper method to split an array of bytes into blocks of the given size, as a List
     * @param rawBytes input array of bytes
     * @param splitSize size of each block
     * @return List of splitSized blocks
     */
    private static List<byte[]> spitByteArray(byte[] rawBytes, int splitSize) {

        List<byte[]> blocks = new ArrayList<>();

        List<Byte> latestBlock = new ArrayList<>();
        int latestBlockCounter = 0;


        for (int i = 0; i < rawBytes.length; i++) {
            byte mByte = rawBytes[i];

            latestBlock.add(mByte);
            latestBlockCounter++;

            boolean refresh = false;

            if (latestBlockCounter == splitSize) {
                refresh = true;
            } else if (i == rawBytes.length - 1) {
                refresh = true;
            }

            if (refresh) {
                byte[] latestBlockArray = new byte[latestBlock.size()];

                for (int j = 0; j < latestBlockArray.length; j++) {
                    latestBlockArray[j] = latestBlock.get(j);
                }

                // add
                blocks.add(latestBlockArray);

                // refresh
                latestBlock = new ArrayList<>();
                latestBlockCounter = 0;
            }
        }


        return blocks;
    }

    /**
     * Helper method to run a cipher on a List of byte arrays and output an array
     *
     * @param blocks list of blocks
     * @param cipher cipher to run
     * @param cipherResultIndex length of the byte[] the cipher takes in
     * @return the entire list of byte[] as a single byte[] that is ciphered
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private static byte[] cipherAndCombine(List<byte[]> blocks, Cipher cipher, int cipherResultIndex) throws BadPaddingException, IllegalBlockSizeException {

        byte[] finalEncrypted = new byte[cipherResultIndex*blocks.size()];

        int counter = 0;
        for (byte[] bytes : blocks) {

            byte[] encrypted = cipher.doFinal(bytes);

            for (byte mByte : encrypted) {
                finalEncrypted[counter] = mByte;
                counter++;

            }
        }

//        System.out.println("Counter stopped at " + counter);
//        System.out.println("Encrypted bytes length: " + finalEncrypted.length);
        return finalEncrypted;
    }

    /**
     * Helper method to get a configured encrypting cipher from a key
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static Cipher getEncryptCipher(Key key, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher encryptCipher = Cipher.getInstance(algorithm);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);

        return encryptCipher;
    }

    /**
     * Helper method to get a configured encrypting cipher from a key at path
     * @param path location of key
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public static Cipher getEncryptCipher(String path, String algorithm, int privateOrPublic) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException {
        Key privateKey = SecurityFileReader.readFileIntoKey(path, privateOrPublic);
        return getEncryptCipher(privateKey, algorithm);
    }

    /**
     * Helper method to get a configured decrypting cipher from a key
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static Cipher getDecryptCipher(Key key, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher;
    }

    /**
     * Helper method to get a configured decrypting cipher from a key at path
     * @param path location of key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     */
    public static Cipher getDecryptCipher(String path, String algorithm, int privateOrPublic) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException {
        Key publicKey = SecurityFileReader.readFileIntoKey(path, privateOrPublic);

        return getDecryptCipher(publicKey, algorithm);
    }




}
