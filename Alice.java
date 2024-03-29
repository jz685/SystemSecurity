//Acknowledgements:
// ----------- AES KEY -------------
//http://stackoverflow.com/questions/15554296/simple-java-aes-encrypt-decrypt-example
//http://stackoverflow.com/questions/5641326/256bit-aes-cbc-pkcs5padding-with-bouncy-castle

// ----------- RSA OAEP -------------
//http://www.java2s.com/Tutorial/Java/0490__Security/RSAexamplewithOAEPPaddingandrandomkeygeneration.htm 

// ----------- Signatures -------------
//https://docs.oracle.com/javase/tutorial/security/apisign/gensig.html

// ------------ Sending objects through sockets -------------
//http://stackoverflow.com/questions/19217420/sending-an-object-through-a-socket-in-java

// -------------RSA CBC mode ---------------
//https://gist.github.com/mythosil/1313541

// -------------IV generation and if it is need to kept secret ----------
// http://security.stackexchange.com/questions/17044/when-using-aes-and-cbc-is-it-necessary-to-keep-the-iv-secret



import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.security.spec.EncodedKeySpec.*;
import java.sql.Timestamp;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

class MSG_NO_ENC implements Serializable{
    public String entity;
    public int msg_num;
    public String msg;

    public MSG_NO_ENC(String ent, String msg_to_send, int num_msg) {
        entity = ent;
        msg_num = num_msg;
        msg = msg_to_send;
    }
    public String toStr() {
        return "" + entity + " || " + msg_num + " || " + msg;
    }
}

class KEY_TRANSPORT implements Serializable{
    public String entity;
    public Timestamp ts;
    public byte[] enc;
    public ArrayList<byte[]> signed;

    public KEY_TRANSPORT(String ent, Timestamp t, byte[] encoded, ArrayList<byte[]> signature) {
        entity = ent;
        ts = t; 
        enc = encoded;
        signed = signature;
    }
    public String toStr() {
        return "" + entity + " || " + ts + " || " + new String(enc) + " || " + signed.toString();
    }
}

class MSG_SYM implements Serializable{
    public String entity;
    public int msg_num;
    public byte[] enc;
    public byte[] theIV;

    public MSG_SYM(String ent, byte[] encode, int num_msg, byte[] generatedIV) {
        entity = ent;
        msg_num = num_msg;
        enc = encode;
        theIV = generatedIV;
    }
    public String toStr() {
        return "" + entity + " || " + msg_num + " || " + new String(enc) + " || " + new String(theIV);
    }
}

class MSG_MAC implements Serializable{
    public String entity;
    public int msg_num;
    public String msg;
    public byte[] macSig;

    public MSG_MAC(String ent, String message, int num_msg, byte[] macS) {
        entity = ent;
        macSig = macS;
        msg_num = num_msg;
        msg = message;
    }
    public String toStr() {
        return "" + entity + " || " + msg_num + " || " + msg + " || " + new String(macSig);
    }
}

class MSG_SYMMAC implements Serializable{
    public String entity;
    public int msg_num;
    public byte[] enc;
    public byte[] theIV;
    public byte[] macSig;

    public MSG_SYMMAC(String ent, byte[] encode, int num_msg, byte[] generatedIV, byte[] macS) {
        entity = ent;
        msg_num = num_msg;
        enc = encode;
        theIV = generatedIV;
        macSig = macS;
    }
    public String toStr() {
        return "" + entity + " || " + msg_num + " || " + new String(enc) + " || " + new String(theIV) + " || " + new String(macSig);
    }
}

public class Alice {

    private static String delimit = "THIS IS A DELIMITER!";
    private static final int rsa_max_bytes = 374;
    private static PublicKey bobpub;
    private static PublicKey alicepub;
    private static PrivateKey alicepriv;
    //private static PrintWriter outputWriter;
    private static ObjectOutputStream outputObject;
    private static SecretKey aesKey;
    private static SecureRandom r = new SecureRandom();
    private static SecretKeySpec macKey;
    private static String mac_str;

    public enum Encrypt_Type {
        NONE, SYM, MAC, SYMMAC
    }

    public static void main(String[] args) throws IOException{
        // Adds a new provider, at a specified position. 1 is most preferred, followed by 2, and so on.
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        // Key init
        try {
            KeyFactory keyGen = KeyFactory.getInstance("RSA", "BC");
            // Generate Bob Public Key
            FileInputStream bobfis = new FileInputStream("./Key/BobPublicKey.key");
            byte[] bobpubArray = new byte[bobfis.available()];
            bobfis.read(bobpubArray);
            bobfis.close();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(bobpubArray);
            bobpub = keyGen.generatePublic(pubKeySpec);
            // Genrate Alice Public Key
            FileInputStream alicefis = new FileInputStream("./Key/AlicePublicKey.key");
            byte[] alicepubArray = new byte[alicefis.available()];
            System.out.println("Length of Alice's public key is " +alicepubArray.length);
            alicefis.read(alicepubArray);
            alicefis.close();
            pubKeySpec = new X509EncodedKeySpec(alicepubArray);
            alicepub = keyGen.generatePublic(pubKeySpec);
            // Generate Alice Private Key
            alicefis = new FileInputStream("./Key/AlicePrivateKey.key");
            byte[] aliceprivArray = new byte[alicefis.available()];
            System.out.println("Length of Alice's private key is " +aliceprivArray.length);
            alicefis.read(aliceprivArray);
            alicefis.close();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(aliceprivArray);
            alicepriv = keyGen.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            System.err.println("Error Reading Keys: " + e.toString());
            return;
        }
        // Accepting portNummber that is less than Integer.MAX_VALUE
        int portNumber = 5005;
        InetAddress localIP = InetAddress.getLocalHost();
        Encrypt_Type enc_type = Encrypt_Type.NONE;
        if (args == null || args.length < 1) {
        } else if (args.length == 1) {
            portNumber = Integer.parseInt(args[0]);
        } else if (args.length > 3) {
            System.err.println("Command Error, Format: $ java Alice <port number> <IP address> <Encryption Type>");
            return;
        } else {
            try {
                portNumber = Integer.parseInt(args[0]);
                localIP = InetAddress.getByName(args[1]);
                if (args[2].equalsIgnoreCase("NONE")) {
                    System.out.println("Using Encryption Type: NONE");
                    enc_type = Encrypt_Type.NONE;
                }
                else if (args[2].equalsIgnoreCase("SYM")) {
                    System.out.println("Using Encryption Type: SYM");
                    enc_type = Encrypt_Type.SYM;
                }
                else if (args[2].equalsIgnoreCase("MAC")) {
                    System.out.println("Using Encryption Type: MAC");
                    enc_type = Encrypt_Type.MAC;
                }
                else if (args[2].equalsIgnoreCase("SYMMAC")) {
                    System.out.println("Using Encryption Type: SYMMAC");
                    enc_type = Encrypt_Type.SYMMAC;
                }
                else {
                    System.err.println("Invalid Encryption Type, Exiting");
                    return;
                }
            } catch (UnknownHostException e) {
                System.err.println("Input Error");
                return;
            }
        }
        // Printing address on screen
        System.out.println("Starting Alice ... with port#: " + portNumber);
        System.out.println("Alice's IP address is := " + localIP.getHostAddress());
        // Create socket
        Socket aliceSocket;
        try {
            aliceSocket = new Socket(localIP, portNumber);
        } catch (IOException e) {
            System.err.println("Cannot create socket");
            return;
        }
        // Create IO
        try {
            //outputWriter = new PrintWriter(aliceSocket.getOutputStream(), true);
            outputObject = new ObjectOutputStream(aliceSocket.getOutputStream());

        } catch (UnknownHostException e) {
            System.err.println("Error with the host");
            return;
        } catch (IOException e) {
            System.err.println("Cannot get I/O for the connection");
            return;
        }
        System.out.println("Connected...");
        // Get std input from typing and transmit

        switch(enc_type) {
            case NONE:
                break;
            case SYM:
                try {
                    key_transport_sym();
                }
                catch (Exception e) {
                    System.err.println("Error in the key transport protocol for option SYM");
                    System.err.println(e.getMessage());
                }
                break;
            case MAC:
                try {
                    mac_transport_sym();
                }
                catch (Exception e) {
                    System.err.println("Error in the mac transport protocol for option MAC");
                    System.err.println(e.getMessage());
                }
                break;
            case SYMMAC:
                try {
                    key_transport_sym();
                }
                catch (Exception e) {
                    System.err.println("Error in the key transport protocol for option SYMMAC");
                    System.err.println(e.getMessage());
                }
                try {
                    mac_transport_sym();
                }
                catch (Exception e) {
                    System.err.println("Error in the mac transport protocol for option MAC");
                    System.err.println(e.getMessage());
                }
                break;
        }

        BufferedReader bufferReader = new BufferedReader(new InputStreamReader(System.in));
        String userInput;
        int message_count = 0;
        System.out.println ("Type Message:");
        while ((userInput = bufferReader.readLine()) != null) {
            switch(enc_type) {
                case NONE: 
                {
                    MSG_NO_ENC next_msg = new MSG_NO_ENC("Bob", userInput, message_count++);
                    try {
                        outputObject.writeObject(next_msg); 
                    }
                    catch (SocketException e) {
                        System.out.println("stream closed, exiting.");
                        return;
                    }
                    if (message_count == Integer.MAX_VALUE) {
                        System.out.println("Max messages have been sent, breaking connection");
                        return;
                    }
                    break;
                }
                case SYM:
                {
                    // Timestamp timeStamp = new Timestamp(System.currentTimeMillis());
                    byte[] ivbytes = generateIV();
                    IvParameterSpec theIV = new IvParameterSpec(ivbytes);
                    byte[] encodedMessage = encode(aesKey, theIV, userInput.getBytes());
                    MSG_SYM next_msg_Enc = new MSG_SYM("Bob", encodedMessage, message_count++, ivbytes);
                    try {
                        outputObject.writeObject(next_msg_Enc); 
                    }
                    catch (SocketException e) {
                        System.out.println("stream closed, exiting");
                        return;
                    }
                    if (message_count == Integer.MAX_VALUE) {
                        System.out.println("Max messages have been sent, breaking connection");
                        return;
                    }
                    break;
                }
                case MAC:
                {
                    try {
                        Mac mac = Mac.getInstance("HMac-SHA224", "BC");
                        mac.init(macKey);
                        // compute the hmac on input data bytes
                        byte[] rawHmac = mac.doFinal(userInput.getBytes());
                        // // base64-encode the hmac
                        // result = Encoding.EncodeBase64(rawHmac);
                        MSG_MAC next_msg_Mac  = new MSG_MAC("Bob", userInput, message_count++, rawHmac);
                        // MSG_MAC next_msg_Mac = new MSG_MAC("Bob", userInput, message_count++, rawHmac);
                        try {
                            outputObject.writeObject(next_msg_Mac); 
                        }
                        catch (SocketException e) {
                            System.out.println("stream closed, exiting");
                            return;
                        }
                        if (message_count == Integer.MAX_VALUE) {
                            System.out.println("Max messages have been sent, breaking connection");
                            return;
                        }
                    } catch (Exception e) {
                        System.err.println("Failed to generate HMAC : " + e.getMessage());
                        return;
                    }
                    break;
                }
                case SYMMAC:
                {
                    try {
                        byte[] ivbytes = generateIV();
                        IvParameterSpec theIV = new IvParameterSpec(ivbytes);
                        byte[] encodedMessage = encode(aesKey, theIV, userInput.getBytes());
                        Mac mac = Mac.getInstance("HMac-SHA224", "BC");
                        mac.init(macKey);
                        byte[] rawHmac = mac.doFinal(encodedMessage);
                        // Send
                        MSG_SYMMAC next_msg_EncMac = new MSG_SYMMAC("Bob", encodedMessage, message_count++, ivbytes, rawHmac);
                        try {
                            outputObject.writeObject(next_msg_EncMac); 
                        }
                        catch (SocketException e) {
                            System.out.println("stream closed, exiting");
                            return;
                        }
                        if (message_count == Integer.MAX_VALUE) {
                            System.out.println("Max messages have been sent, breaking connection");
                            return;
                        }
                    } catch (Exception e) {
                        System.err.println("Failed to generate SYMMAC : " + e.getMessage());
                        return;
                    }
                    break;
                }
            }
        }
        //outputWriter.close();
        outputObject.close();
        bufferReader.close();
        aliceSocket.close();
    }

    // https://gist.github.com/mythosil/1313541
    private static byte[] encode(SecretKey skey, IvParameterSpec iv, byte[] data) {
        return process(Cipher.ENCRYPT_MODE, skey, iv, data);
    }

    private static byte[] decode(SecretKey skey, IvParameterSpec iv, byte[] data) {
        return process(Cipher.DECRYPT_MODE, skey, iv, data);
    }

    private static byte[] process(int mode, SecretKey skey, IvParameterSpec iv, byte[] data) {
        // SecretKeySpec key = new SecretKeySpec(skey.getBytes(), "AES");
        // AlgorithmParameterSpec param = new IvParameterSpec(iv.getBytes());
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, skey, iv);
            return cipher.doFinal(data);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static byte[] generateIV() {

        byte[] newSeed = r.generateSeed(16);
        r.setSeed(newSeed);

        byte[] byteIV = new byte[16];
        r.nextBytes(byteIV);
        // IvParameterSpec IV = new IvParameterSpec(byteIV);
        return byteIV;
    }

    private static void mac_transport_sym() throws Exception{
        //// ------- GENERATE AES KEY --------
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HMac-SHA224", "BC");
            SecretKey signingKey = keyGen.generateKey();
            byte[] signingKeyByteArray = signingKey.getEncoded();
            mac_str = Base64.getEncoder().encodeToString(signingKeyByteArray);
            macKey = macKey = new SecretKeySpec(signingKeyByteArray, "HMac-SHA224");
            // Print Key to verify
            System.out.println("The MAC Key is: " + Base64.getEncoder().encodeToString(macKey.getEncoded()));
        } catch (Exception e) {
            System.err.println("Key Generation Error " + e.toString());
            return;
        }
        //// ------- ENCRYPT --------
        String b = "Bob";
        String a = "Alice";
        Timestamp timeStamp = new Timestamp(System.currentTimeMillis());
        String to_encrypt = a + delimit + mac_str;
        byte[] encrypt_input = to_encrypt.getBytes();
        SecureRandom random = new SecureRandom();
        String encrypted_text_str;
        byte[] encrypted_text;
        ArrayList<byte[]> signed = new ArrayList<byte[]>();
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, bobpub, random);
            encrypted_text = cipher.doFinal(encrypt_input);
            encrypted_text_str = new String(encrypted_text);
            // System.out.println("Encrypted!!!  Text is: ");
            // System.out.println(encrypted_text_str);
            //Sign data
            Signature dsa = Signature.getInstance("RSA", "BC"); 
            // System.out.println("BEFORE ALICE PRIV");
            dsa.initSign(alicepriv);
            // ------------- SIGNING -----------------
            // System.out.println("AFTER ALICE PRIV");
            String to_sign = b + delimit + timeStamp + delimit + encrypted_text_str;
            int string_ind = rsa_max_bytes;
            String to_sign_substr = "";
            for (int i = 0; i <= to_sign.length()/rsa_max_bytes; i++) {
                // System.out.println("In loop");
                if (string_ind > to_sign.length()) {
                    string_ind = to_sign.length();
                }
                to_sign_substr = to_sign.substring((i * rsa_max_bytes), string_ind);
                dsa.update(to_sign_substr.getBytes(), 0, to_sign_substr.length());
                byte[] signed_sub_bytes = dsa.sign();
                signed.add(signed_sub_bytes);
                // System.out.println("NUMBER in the arraylist was " + (new String(signed_sub_bytes)));
            }
        } catch (Exception e) {
            System.err.println("Encription Error " + e.toString());
            return;
        }
        //Generate final string
        // System.err.println("BEFORE TRANSPORT OBJ");
        KEY_TRANSPORT transport_obj = new KEY_TRANSPORT(b, timeStamp, encrypted_text, signed);
        outputObject.writeObject(transport_obj); 
    }

    private static void key_transport_sym() throws Exception{
        //// ------- GENERATE AES KEY --------
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.init(256, random);
            aesKey = keyGen.generateKey();
            // Print Key to verify
            System.out.println("The AES Key is: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        } catch (Exception e) {
            System.err.println("Key Generation Error " + e.toString());
            return;
        }

        //// ------- ENCRYPT --------
        byte[] aesKeyByteArray = aesKey.getEncoded();
        // String kAB_str = new String(aesKeyByteArray);
        String kAB_str = Base64.getEncoder().encodeToString(aesKeyByteArray);
        String format = aesKey.getFormat();
        String b = "Bob";
        String a = "Alice";
        Timestamp timeStamp = new Timestamp(System.currentTimeMillis());
        String to_encrypt = a + delimit + kAB_str;
        byte[] encrypt_input = to_encrypt.getBytes();

        SecureRandom random = new SecureRandom();
        String encrypted_text_str;
        byte[] encrypted_text;
        ArrayList<byte[]> signed = new ArrayList<byte[]>();
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, bobpub, random);
            encrypted_text = cipher.doFinal(encrypt_input);
            encrypted_text_str = new String(encrypted_text);
            //Sign data
            Signature dsa = Signature.getInstance("RSA", "BC"); 
            dsa.initSign(alicepriv);
            // ------------- SIGNING -----------------
            String to_sign = b + delimit + timeStamp + delimit + encrypted_text_str;
            int string_ind = rsa_max_bytes;
            String to_sign_substr = "";
            for (int i = 0; i <= to_sign.length()/rsa_max_bytes; i++) {
                if (string_ind > to_sign.length()) {
                    string_ind = to_sign.length();
                }
                to_sign_substr = to_sign.substring((i * rsa_max_bytes), string_ind);
                dsa.update(to_sign_substr.getBytes(), 0, to_sign_substr.length());
                byte[] signed_sub_bytes = dsa.sign();
                signed.add(signed_sub_bytes);
                // System.out.println("NUMBER in the arraylist was " + (new String(signed_sub_bytes)));
            }
        } catch (Exception e) {
            System.err.println("Encription Error " + e.toString());
            return;
        }
        //Generate final string
        // System.err.println("BEFORE TRANSPORT OBJ");
        KEY_TRANSPORT transport_obj = new KEY_TRANSPORT(b, timeStamp, encrypted_text, signed);
        outputObject.writeObject(transport_obj); 
    }
}