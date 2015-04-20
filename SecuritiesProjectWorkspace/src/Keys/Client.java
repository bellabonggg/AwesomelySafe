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
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class Client {
    private static Cipher ecipher;
    private static Cipher dcipher;
//
    private static SecretKey key;
    private static ArrayList<byte []> byteblocks = new ArrayList<byte []>();
    private static ArrayList<byte []> encryptblocks = new ArrayList<byte []>();
    private static int counter;
    
    public static void main(String[] args) throws IOException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeySpecException {
       

        

        // Create cert object
    	CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    	//Read your own file
    	InputStream inStream = new FileInputStream("C:\\Users\\Peh\\workspaceLuna\\NetworkAssignment\\src\\CA.crt.txt");
    	X509Certificate cert = (X509Certificate)certFactory.generateCertificate(inStream);
    	
    	//Check cert validity
    	cert.checkValidity();
    	
//    	//Initialize public key
//    	PublicKey key = cert.getPublicKey();
//    	
//    	//Verify public key
//    	cert.verify(key);
    	
    	
        FileInputStream fis = null;
        byte[] encodedKey = null;
        File f = new File("C:\\Users\\Peh\\workspaceLuna\\NetworkAssignment\\src\\publicServer.der");
        encodedKey = new byte[(int)f.length()];

        fis = new FileInputStream(f);
        fis.read(encodedKey);
        fis.close();

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(encodedKey));
    	
       // String fileName = "yourFile";
        File filePrivateKey = new File("C:\\Users\\Peh\\workspaceLuna\\NetworkLab2\\src\\encryption.txt");
        
        fis = new FileInputStream("C:\\Users\\Peh\\workspaceLuna\\NetworkLab2\\src\\encryption.txt");
        byte[] dataByte = new byte[(int) filePrivateKey.length()];
        fis.read(dataByte);
        System.out.println(Arrays.toString(dataByte));
        
        
        //Split byte array into blocks of 117 byte
        while(counter<=dataByte.length){
        	
        	byte [] buffer = new byte[117];
        	int remaining = dataByte.length-counter; 
        	if(remaining<117){
        		buffer= new byte[remaining];
            	for(int i=0;i<remaining;i++){
            		buffer[i]=dataByte[counter];
            		counter++;
            	}
            	byteblocks.add(buffer);
            	break;
        	}
        	
        	for(int i=0;i<117;i++){
        		buffer[i]=dataByte[counter];
        		counter++;
        	}
        	byteblocks.add(buffer);

        }
        for(byte[] b:byteblocks){
        	System.out.println(Arrays.toString(b));
        }
        
      //TODO: Create cipher object, configure it to do DES cryptography, set operation mode to encryption
        Cipher desCipher = ecipher.getInstance("RSA/ECB/PKCS1Padding");
        desCipher.init(Cipher.ENCRYPT_MODE,key);
        
//TODO: Do the DES encryption here, by calling method Cipher.doFinal(). Convert encrypted byte[] to Base64 format
        for(byte [] b:byteblocks){
        	byte [] dataByte2=desCipher.doFinal(b);
        	System.out.println(dataByte2.length);
        	encryptblocks.add(dataByte2);
        	}
        
        //Create clientsocket
        AwesomeClientSocket clientSocket = new AwesomeClientSocket("localhost", 5555);
        byte [] sendblock = new byte[128*encryptblocks.size()];
        System.out.println(sendblock.length);
        //Combine encrypted blocks
        int counter =0;
        for(int i=0;i<encryptblocks.size();i++){
        	for(int j=0;j<encryptblocks.get(i).length;j++){
        		sendblock[counter]= encryptblocks.get(i)[j];
        		counter++;
        		System.out.println(counter);
        	}
        }
        
        System.out.println(Arrays.toString(sendblock));
        //Send block
        clientSocket.sendByteArray(sendblock);


    }
    

}
