import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.security.spec.EncodedKeySpec.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Alice {

    public enum Encrypt_Type {
        NONE, SYM, MAC, SYMMAC
    }

    public static void main(String[] args) throws IOException{
        // Adds a new provider, at a specified position. 1 is most preferred, followed by 2, and so on.
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        // Key init
        PublicKey alicepub;
        PublicKey bobpub;
        PrivateKey alicepriv;
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
            // Generate Alice Private Key
            alicefis = new FileInputStream("./Key/alicePrivateKey.key");
            byte[] aliceprivArray = new byte[alicefis.available()];
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
        PrintWriter outputWriter;
        try {
            outputWriter = new PrintWriter(aliceSocket.getOutputStream(), true);
        } catch (UnknownHostException e) {
            System.err.println("Error with the host");
            return;
        } catch (IOException e) {
            System.err.println("Cannot get I/O for the connection");
            return;
        }
        System.out.println("Connected...");
        // Get std input from typing and transmit


        BufferedReader bufferReader = new BufferedReader(new InputStreamReader(System.in));
        String userInput;
        int message_count = 0;
        System.out.println ("Type Message 'Quit' to quit");
        while ((userInput = bufferReader.readLine()) != null) {
            if (userInput.equals("Quit")) {
                break;
            }
            switch(enc_type) {
                case NONE:
                    outputWriter.println((message_count++) + "," + userInput);
                    if (message_count == Integer.MAX_VALUE) {
                        System.out.println("Max messages have been sent, breaking connection");
                        //NOTE: Do we just want to send over a different session key on max messages?
                        return;
                    }
                    break;
                case SYM:
                case MAC:
                case SYMMAC:
            }
        }
        outputWriter.close();
        bufferReader.close();
        aliceSocket.close();
    }
}