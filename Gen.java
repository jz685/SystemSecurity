import java.io.*;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Gen {
    // Compile: javac -cp  bcprov-jdk15on-154.jar:. Gen.java
    // Run: java -cp  bcprov-jdk15on-154.jar:. Gen

    // private static final String salt = "A long, but constant phrase that will be used each time as the salt.";
    // private static final int iterations = 2000;
    // private static final int keyLength = 256;
    // private static final SecureRandom random = new SecureRandom();

    public static void main(String [] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        // String passphrase = "The quick brown fox jumped over the lazy brown dog";
        // String plaintext = "hello world";
        // byte [] ciphertext = encrypt(passphrase, plaintext);
        // String recoveredPlaintext = decrypt(passphrase, ciphertext);

        // System.out.println(recoveredPlaintext);

        try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);
			// Generate Alice
			KeyPair alicepair = keyGen.generateKeyPair();
			// System.out.println("Public key " + pair.getPublic());
			// System.out.println("Private key " + pair.getPrivate());
			PrivateKey alicepriv = alicepair.getPrivate();
			PublicKey alicepub = alicepair.getPublic();
			byte[] alicepubBytes = alicepub.getEncoded();
			byte[] aliceprivBytes = alicepriv.getEncoded();
			// Save
			FileOutputStream alicefos = new FileOutputStream("./Key/AlicePublicKey.key");
			alicefos.write(alicepubBytes);
			alicefos.close();
			alicefos = new FileOutputStream("./Key/AlicePrivateKey.key");
			alicefos.write(aliceprivBytes);
			alicefos.close();
			// Generate Bob
			// Generate Alice
			KeyPair bobpair = keyGen.generateKeyPair();
			// System.out.println("Public key " + pair.getPublic());
			// System.out.println("Private key " + pair.getPrivate());
			PrivateKey bobpriv = bobpair.getPrivate();
			PublicKey bobpub = bobpair.getPublic();
			byte[] bobpubBytes = bobpub.getEncoded();
			byte[] bobprivBytes = bobpriv.getEncoded();
			// Save
			FileOutputStream bobfos = new FileOutputStream("./Key/BobPublicKey.key");
			bobfos.write(bobpubBytes);
			bobfos.close();
			bobfos = new FileOutputStream("./Key/BobPrivateKey.key");
			bobfos.write(bobprivBytes);
			bobfos.close();
			// System.out.println("Private Key: \n" + priv.toString());
			// System.out.println("Public Key: \n" + pub.toString());
			// System.out.println("Public Key Algorithm is: " + pub.getAlgorithm() + ", and the value is: " + pub.getFormat())
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }

    // private static byte [] encrypt(String passphrase, String plaintext) throws Exception {
    //     SecretKey key = generateKey(passphrase);

    //     Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING");
    //     cipher.init(Cipher.ENCRYPT_MODE, key, generateIV(cipher), random);
    //     return cipher.doFinal(plaintext.getBytes());
    // }

    // private static String decrypt(String passphrase, byte [] ciphertext) throws Exception {
    //     SecretKey key = generateKey(passphrase);

    //     Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING");
    //     cipher.init(Cipher.DECRYPT_MODE, key, generateIV(cipher), random);
    //     return new String(cipher.doFinal(ciphertext));
    // }

    // private static SecretKey generateKey(String passphrase) throws Exception {
    //     PBEKeySpec keySpec = new PBEKeySpec(passphrase.toCharArray(), salt.getBytes(), iterations, keyLength);
    //     SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC");
    //     return keyFactory.generateSecret(keySpec);
    // }

    // private static IvParameterSpec generateIV(Cipher cipher) throws Exception {
    //     byte [] ivBytes = new byte[cipher.getBlockSize()];
    //     random.nextBytes(ivBytes);
    //     return new IvParameterSpec(ivBytes);
    // }

}