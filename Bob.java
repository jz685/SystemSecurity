//Acknowledgements:
// Byte array to key: http://stackoverflow.com/questions/2778256/how-to-convert-byte-array-to-key-format
//http://stackoverflow.com/questions/19217420/sending-an-object-through-a-socket-in-java

// -------------RSA CBC mode ---------------
//https://gist.github.com/mythosil/1313541

import java.io.*;
import java.net.*;
import java.util.*;
import Util.Helper;
import java.security.*;
import java.security.spec.*;
import java.security.spec.EncodedKeySpec.*;
import java.sql.Timestamp;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
}

class MSG_MAC implements Serializable{
    public String entity;
    public int msg_num;
    public String msg;
    public byte[] macSig;
    public String mac_str;


    public MSG_MAC(String ent, String message, int num_msg, byte[] macS, String mac) {
        entity = ent;
        macSig = macS;
        msg_num = num_msg;
        msg = message;
        mac_str = mac;
    }
}

public class Bob {

    private static final long TWO_MINUTES = 2 * 60 * 1000;
    private static final String delimit = "THIS IS A DELIMITER!";
    private static final int rsa_max_bytes = 374;
    private static ObjectInputStream objInp;
    private static PublicKey bobpub;
    private static PrivateKey bobpriv;
    private static PublicKey alicepub;
    private static SecretKey symKey;



    public enum Encrypt_Type {
        NONE, SYM, MAC, SYMMAC
    }

    public static void main(String[] args) throws IOException{
        Encrypt_Type enc_type = Encrypt_Type.NONE;
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
            alicefis.read(alicepubArray);
            alicefis.close();
            pubKeySpec = new X509EncodedKeySpec(alicepubArray);
            alicepub = keyGen.generatePublic(pubKeySpec);

            // Generate Bob Private Key
            bobfis = new FileInputStream("./Key/BobPrivateKey.key");
            byte[] bobprivArray = new byte[bobfis.available()];
            bobfis.read(bobprivArray);
            bobfis.close();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bobprivArray);
            bobpriv = keyGen.generatePrivate(privateKeySpec);

        } catch (Exception e) {
            System.err.println("Error Reading Keys: " + e.toString());
            return;
        }

        // Accepting portNummber that is less than Integer.MAX_VALUE
        int portNumber = 3000;
        if (args.length > 2) {
            System.err.println("Command Error, Format: $ java Bob <port number>");
            return;
        } else {
            try {
                portNumber = Integer.parseInt(args[0]);
                if (args[1].equalsIgnoreCase("NONE")) {
                    System.out.println("Using Encryption Type: NONE");
                    enc_type = Encrypt_Type.NONE;
                }
                else if (args[1].equalsIgnoreCase("SYM")) {
                    System.out.println("Using Encryption Type: SYM");
                    enc_type = Encrypt_Type.SYM;
                }
                else if (args[1].equalsIgnoreCase("MAC")) {
                    System.out.println("Using Encryption Type: MAC");
                    enc_type = Encrypt_Type.MAC;
                }
                else if (args[1].equalsIgnoreCase("SYMMAC")) {
                    System.out.println("Using Encryption Type: SYMMAC");
                    enc_type = Encrypt_Type.SYMMAC;
                }
                else {
                    System.err.println("Invalid Encryption Type, Exiting");
                    return;
                }
            }
            catch (Exception e) {
                System.err.println("Error, Invalid Input");
                return;
            }
        }
        // Printing address on screen
        System.out.println("Starting Bob ... with port#: " + portNumber);
        InetAddress localIP = InetAddress.getLocalHost();
        System.out.println("Bob's IP address is := " + localIP.getHostAddress());
        // Bind
        ServerSocket bobSocket;
        try {
            bobSocket = new ServerSocket(portNumber);
        } catch (IOException e) {
            System.err.println("Cannot bind port...");
            return;
        }
        // Listen and Accept
        Socket clientSocket;
        try {
            clientSocket = bobSocket.accept();
        } catch (IOException e) {
            System.err.println("Cannot listen and/or accept...");
            return;
        }
        System.out.println("Connected...");
        // Read
        //BufferedReader inputReader;
        try {
            //inputReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            objInp = new ObjectInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.err.println("Cannot Read...");
            return;
        }
        int msg_index = 0;
        String inputLine;

        switch (enc_type) {
            case NONE:
                try {
                    read_non_enc_msgs();
                }
                catch (Exception e) {
                    System.err.println("Error in receiving non encrypted messages:" + e.getMessage());
                }
                break;
            case SYM:
                try {
                    KEY_TRANSPORT key_transport = (KEY_TRANSPORT) objInp.readObject();
                    int response = check_sym_key_transport(key_transport);
                    if (response == -1) {
                        return;
                    }
                }
                catch (Exception e) {
                    System.err.println("Error in receiving the key_transport from Alice.  Shutting down");
                    return;
                }
                try {
                    read_enc_msgs();
                } 
                catch (Exception e) {
                    System.err.println("Error in receiving encrypted messages:" + e.getMessage());
                }
                break;
            case MAC:
                try {
                    read_mac_msgs();
                } 
                catch (Exception e) {
                    System.err.println("Error in receiving mac messages:" + e.getMessage());
                }
                break;
            case SYMMAC:
                break;
        }
        /*while ((inputLine = inputReader.readLine()) != null) {
            switch (enc_type) {
                case NONE: 
                    if (inputLine == "Quit") {
                        inputReader.close();
                        clientSocket.close();
                        return;
                    }
                    int msg_num = -1;
                    String msg_num_str = inputLine.split(",")[0];
                    try {
                        msg_num = Integer.parseInt(msg_num_str);
                    }
                    catch (NumberFormatException e) {
                        System.err.println("Received a message with no index.  Suspecting attack, shutting down connection");
                        inputReader.close();
                        clientSocket.close();
                        return;
                    }
                    if (msg_num != (msg_index++)) {
                        System.out.println("Received a message with the wrong index.  Suspecting attack, shutting down connection");
                        inputReader.close();
                        clientSocket.close();
                        return;
                    }
                    System.out.println("Message Number " + msg_num + " received!");
                    System.out.println(inputLine.substring(msg_num_str.length()+1, inputLine.length()));
                    break;
                case SYM:
                case MAC:
                case SYMMAC:
            }
        }*/
        //inputReader.close();
        objInp.close();
        clientSocket.close();
    }

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

    private static void read_non_enc_msgs() throws Exception{
        int msg_num = 0;
        MSG_NO_ENC next_message;
        while ((next_message = (MSG_NO_ENC)objInp.readObject()) != null) {
            if (msg_num++ != next_message.msg_num) {
                System.err.println("Received a message with the wrong message number.  Suspecting attack, shutting down connection.");
                return;
            }
            if (!(next_message.entity).equals("Bob")) {
                System.err.println("Wrong recipient in transmission protocol.  Shutting down connection.");
                return;
            }
            System.out.println("Printing message number " + msg_num + ":");
            System.out.println(next_message.msg);
        }
        return;
    }

    private static void read_mac_msgs() throws Exception{
        int msg_num = 0;
        MSG_MAC next_message;
        while ((next_message = (MSG_MAC)objInp.readObject()) != null) {
            if (msg_num++ != next_message.msg_num) {
                System.err.println("Received a message with the wrong message number.  Suspecting attack, shutting down connection.");
                return;
            }
            if (!(next_message.entity).equals("Bob")) {
                System.err.println("Wrong recipient in transmission protocol.  Shutting down connection.");
                return;
            }
            String msg = next_message.msg;
            byte[] macSig = next_message.macSig;
            String mac_str = next_message.mac_str;
            
            byte[] macKeyBytes = Base64.getDecoder().decode(mac_str);
            SecretKeySpec macKey = new SecretKeySpec(macKeyBytes, "HmacSHA1"); 
            Mac mac = Mac.getInstance("HmacSHA1", "BC");
            mac.init(macKey);
            byte[] rawHmac = mac.doFinal(msg.getBytes());
            if (Arrays.equals(rawHmac, macSig)) {
            // if (true) {
                System.out.println("Printing message number " + msg_num + ":");
                System.out.println("Message: " + msg);
                // System.out.println("MAC: " + new String(macSig));
                System.out.println("----------");
            } else {
                System.out.println("MAC sig does not match, we are under attack, abort.");
                return;
            }

        }
        return;
    }

    private static void read_enc_msgs() throws Exception{
        int msg_num = 0;
        MSG_SYM next_message;
        while ((next_message = (MSG_SYM)objInp.readObject()) != null) {
            if (msg_num++ != next_message.msg_num) {
                System.err.println("Received a message with the wrong message number.  Suspecting attack, shutting down connection.");
                return;
            }
            if (!(next_message.entity).equals("Bob")) {
                System.err.println("Wrong recipient in transmission protocol. Shutting down connection.");
                return;
            }
            byte[] ivbytes = next_message.theIV;
            IvParameterSpec iv = new IvParameterSpec(ivbytes);
            byte[] encMessage = next_message.enc;
            byte[] decodedMessage = decode(symKey, iv, encMessage);

            System.out.println("Printing message number " + msg_num + ":");
            // System.out.println("Encoded Message: " + new String(encMessage));
            System.out.println("Dncoded Message: " + new String(decodedMessage));
            System.out.println("----------");

        }
        return;
    }


    private static int check_sym_key_transport(KEY_TRANSPORT key_t) throws Exception{
        if (!(key_t.entity).equals("Bob")) {
            System.err.println("Wrong recipient in Key transmission protocol.  Shutting down connection.");
            return -1;
        }
        Timestamp ts = key_t.ts;
        long millis_sent = ts.getTime();
        long millis_sent_plus_two = millis_sent + TWO_MINUTES;
        long current_time = System.currentTimeMillis();

        if (!(current_time >= millis_sent && current_time <= millis_sent_plus_two)) {
            System.err.println("The timestamp is past due.  Shutting down connection.");
            return -1;
        }

        String kABStr;
        try {
            //DECRYPT MSG
            //System.out.println("IN DECRYPT");
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, bobpriv);
            //System.out.println("out of init");
            byte[] encrypted = key_t.enc;
            byte[] unencrypt_bytes = cipher.doFinal(encrypted);
            String unencrypt_str = new String(unencrypt_bytes);
            String should_be_alice = unencrypt_str.split(delimit)[0];
            //System.out.println("unencrypted str is " + unencrypt_str);
            //System.out.println("Should be alice is " + should_be_alice);
            if (!should_be_alice.equals("Alice")) {
                System.out.println("Encrypted string should have been sent from alice");
                return -1;
            }
            kABStr = unencrypt_str.split(delimit)[1];
            byte[] symKeyBytes = Base64.getDecoder().decode(kABStr);
            symKey = new SecretKeySpec(symKeyBytes, "AES"); 
            // symKey = new SecretKeySpec(kABStr.getBytes(), "AES");
            //Print the Key
            System.out.println("The Key is: " + Base64.getEncoder().encodeToString(symKey.getEncoded()));

            //CHECK SIGNATURE
            Signature sig = Signature.getInstance("RSA", "BC");
            sig.initVerify(alicepub); //public key of A
            
            String signed_str = "Bob" + delimit + ts + delimit + (new String(encrypted));
            int string_ind = rsa_max_bytes;
            String signed_substr;
            for (int i = 0; i <= signed_str.length()/rsa_max_bytes; i++) {
                if (string_ind > signed_str.length()) {
                    string_ind = signed_str.length();
                }
                signed_substr = signed_str.substring((i * rsa_max_bytes), string_ind);
                sig.update(signed_substr.getBytes(), 0, signed_substr.length());
                boolean verified = sig.verify(key_t.signed.get(i)); 
                //System.out.println("NUMBER in the arraylist was " + new String(key_t.signed.get(i)));
                //System.out.println("For iteration " + i + ", the output was " + verified);
                if (verified != true) {
                    System.err.println("Signature does not check out.  Closing connection.");
                    return -1;
                }
            }
        } catch (Exception e) {
            System.err.println("Error with the sym key: " + e.toString());
            return -1;
        }
        return 1;
    }
}