package deprecated;

import AwesomeSockets.AwesomeServerSocket;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;




public class Server {
    private static Cipher ecipher;
    private static Cipher dcipher;
//
    private static SecretKey key;
    private static ArrayList<byte []> byteblocks = new ArrayList<byte []>();
    private static ArrayList<byte []> encryptblocks = new ArrayList<byte []>();
    private static int counter;
    
    public static void main(String[] args) throws IOException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeySpecException {
       

        AwesomeServerSocket serverSocket = new AwesomeServerSocket(5555);

        serverSocket.acceptClient();
        
        byte[] readMessage = serverSocket.readByteArrayForClient(0);
        System.out.println(readMessage.length);
        System.out.println(Arrays.toString(readMessage));
        
        FileInputStream fis = null;
        byte[] encodedKey = null;
        File f = new File("src/keys/privateServer.der");
        encodedKey = new byte[(int)f.length()];

        fis = new FileInputStream(f);
        fis.read(encodedKey);
        fis.close();

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
        
        
        
//
//        // Create cert object
//    	CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
//    	//Read your own file
//    	InputStream inStream = new FileInputStream("C:\\Users\\Peh\\workspaceLuna\\NetworkAssignment\\src\\CA.crt.txt");
//    	X509Certificate cert = (X509Certificate)certFactory.generateCertificate(inStream);
//
//    	//Check cert validity
//    	cert.checkValidity();
//
//    	//Initialize public key
//    	PublicKey key = cert.getPublicKey();
//
//    	//Verify public key
//    	cert.verify(key);
//

    	
//    	byte[] decryptedblock = decryptblock(readMessage,privateKey);
//    	System.out.println(new String(decryptedblock));

        Cipher desCipher = ecipher.getInstance("RSA/ECB/PKCS1Padding");
        //TODO: set the cipher object to decryption mode
        desCipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] answer = desCipher.doFinal(readMessage);


        System.out.println(Arrays.toString(answer));
        serverSocket.closeServer();

    	
        
        

        
        

    }
    
    public static byte[] decryptblock(byte [] dataByte,PrivateKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
        int counter =0;
    	//Split byte array into blocks of 117 byte
        while(counter<=dataByte.length){
        	System.out.println(counter);
        	byte [] buffer = new byte[128];
        	int remaining = dataByte.length-counter; 
        	if(remaining<128){
        		buffer= new byte[remaining];
            	for(int i=0;i<remaining;i++){
            		buffer[i]=dataByte[counter];
            		counter++;
            	}
            	byteblocks.add(buffer);
            	break;
        	}
        	
        	for(int i=0;i<128;i++){
        		buffer[i]=dataByte[counter];
        		counter++;
        	}
        	byteblocks.add(buffer);

        }
    	Cipher desCipher = ecipher.getInstance("RSA/ECB/PKCS1Padding");
    	//TODO: set the cipher object to decryption mode
        desCipher.init(Cipher.DECRYPT_MODE, key);
        //TODO:  Do the DES decryption
        for(int i=0;i<byteblocks.size();i++){
        	
        	encryptblocks.add(desCipher.doFinal(byteblocks.get(i)));
    }
        byte [] sendblock = new byte[dataByte.length];
        
        //Combine encrypted blocks
        counter =0;
        for(int i=0;i<encryptblocks.size();i++){
        	for(int j=0;j<encryptblocks.get(i).length;j++){
        		sendblock[counter]= encryptblocks.get(i)[j];
        		counter++;
        		if(counter == 423){
        			break;
        		}
        	}
        }  
        return sendblock;
    
    }
    
}
