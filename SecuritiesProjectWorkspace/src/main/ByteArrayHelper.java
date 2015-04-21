package main;

/**
 * Created by JiaHao on 21/4/15.
 */
public class ByteArrayHelper {

    public static byte[][] splitMessage(byte[] inp, int lengthOfFirstPart) {

        byte[] hash = new byte[lengthOfFirstPart];
        byte[] message = new byte[inp.length - lengthOfFirstPart];


        for (int i = 0; i < inp.length; i++) {

            if (i < lengthOfFirstPart) {
                hash[i] = inp[i];
            } else {
                message[i - hash.length] = inp[i];
            }
        }

        byte[][] result = new byte[2][];

        result[0] = hash;
        result[1] = message;
        return result;
    }



    public static byte[] concatenateBytes(byte[] first, byte[] second) {

        byte[] result = new byte[first.length + second.length];

        for (int i = 0; i < result.length; i++) {
            byte toPut;
            if (i < first.length) {
                toPut = first[i];
            } else {
                toPut = second[i-first.length];
            }
            result[i] = toPut;
        }
        return result;
    }

}
