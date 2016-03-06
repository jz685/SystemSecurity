import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.security.*;
import java.security.spec.*;
import java.security.spec.EncodedKeySpec.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Mallory extends Thread{

    public static Queue<String> unread_q;
    public static List<String> message_list;
    public static PrintWriter outputWriter;
    public static boolean still_receiving;
    private static Lock q_lock;

 
    public void run() {
        System.out.println("Thread Started");
        BufferedReader bufferReader = new BufferedReader(new InputStreamReader(System.in));
        String userInput;
        boolean waiting = true;

        try {
            while(still_receiving) {
                q_lock.lock();
                if (!unread_q.isEmpty()) {
                    waiting = false;
                    //Get next unread message
                    String nextMessage = unread_q.remove();
                    message_list.add(nextMessage);
                    q_lock.unlock();

                    //Print message
                    System.out.println("Showing next unread message:");
                    System.out.println(nextMessage);

                    //Wait until told what to do about the message
                    boolean proper_response = false;
                    while (!proper_response) {
                        System.out.println("Type p to pass, d to delete, m to modify");
                        userInput = bufferReader.readLine(); 
                        if (userInput.equalsIgnoreCase("p")) {
                            outputWriter.println(nextMessage);
                            proper_response = true;
                        }
                        else if (userInput.equalsIgnoreCase("d")) {
                            proper_response = true;
                        }
                        else if (userInput.equalsIgnoreCase("m")) {
                            proper_response = true;
                            System.out.println("Enter a string to pass along:");
                            userInput = bufferReader.readLine();
                            outputWriter.println(userInput);
                        }
                    }
                }
                else if (waiting == false) {
                    q_lock.unlock();
                    int saved_size = message_list.size();
                    if (saved_size == 0) {
                        continue;
                    }
                    System.out.println("There are no unread messages for you to view.  Type s to view a saved one or w to wait for a new message.");
                    userInput = bufferReader.readLine();
                    if (userInput.equalsIgnoreCase("s")) {
                        boolean got_num = false;
                        int read_num = -1;
                        while (!got_num) {
                            System.out.println("Type a number between 0 and " + (message_list.size()-1) + " inclusive to view the corresponding message.");
                            userInput = bufferReader.readLine();
                            try {
                                read_num = Integer.parseInt(userInput);
                                if (read_num < 0 || read_num >= message_list.size()) {
                                    System.out.println("Error: You did not enter a number in the proper range.  Try again.");
                                }
                                else {
                                    System.out.println("Printing out message number " + read_num + ":");
                                    System.out.println(message_list.get(read_num));
                                    got_num = true;
                                }
                            }
                            catch (NumberFormatException e) {
                                System.out.println("Error: You did not enter a number.  Try again.");
                            }
                        }
                    }
                    else if (userInput.equalsIgnoreCase("w")) {
                        System.out.println("Ok, we will wait until a message arrives");
                        waiting = true;
                    }
                }
                else {
                    q_lock.unlock();
                }
            }
        }
        catch (IOException e) {
            System.err.println("Reached an IO exception, exiting");
            still_receiving = false;
            return;

        }
    }

    public static void main(String[] args) throws IOException{
        // Adds a new provider, at a specified position. 1 is most preferred, followed by 2, and so on.
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        // Key init
        PublicKey alicepub;
        PublicKey bobpub;
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

        } catch (Exception e) {
            System.err.println("Error Reading Keys: " + e.toString());
            return;
        }
        // Accepting portNummber that is less than Integer.MAX_VALUE
        int selfportNumber = 2000;
        InetAddress selflocalIP = InetAddress.getLocalHost();
        int targetportNumber = 3000;
        InetAddress targetlocalIP = InetAddress.getLocalHost();
        still_receiving = true;
        message_list = new ArrayList<String>();
        q_lock = new ReentrantLock();
        // Handle inputs
        if (args == null || args.length == 0) {
            // Nothing
        } else if (args.length == 1) {
            selfportNumber = Integer.parseInt(args[0]);
        } else if (args.length == 2) {
            try {
                targetportNumber = Integer.parseInt(args[0]);
                targetlocalIP = InetAddress.getByName(args[1]);
            } catch (UnknownHostException e) {
                System.err.println("Input Error");
                return;
            }
        } else if (args.length == 3) {
            try {
                targetportNumber = Integer.parseInt(args[0]);
                targetlocalIP = InetAddress.getByName(args[1]);
                selfportNumber = Integer.parseInt(args[2]);
            } catch (UnknownHostException e) {
                System.err.println("Input Error");
                return;
            }
        } else {
            System.out.println("Input format One: $ java Bob");
            System.out.println("Input format Two: $ java Bob <self port number>");
            System.out.println("Input format Three: $ java Bob <target port number> <target IP address>");
            System.out.println("Input format Four: $ java Bob <target port number> <target IP address> <self port number>");
            return;
        }
        // Printing address on screen
        System.out.println("Starting Mallory ... with port#: " + selfportNumber);
        System.out.println("Mallory's IP address is := " + selflocalIP.getHostAddress());
        System.out.println("Target port#: " + targetportNumber);
        System.out.println("Target IP address:= " + targetlocalIP.getHostAddress());
        //---- Send ----//
        // Connect to Target
        Socket mallorySenSocket;
        try {
            mallorySenSocket = new Socket(targetlocalIP, targetportNumber);
        } catch (IOException e) {
            System.err.println("Cannot create socket");
            return;
        }
        // Create IO
        try {
            outputWriter = new PrintWriter(mallorySenSocket.getOutputStream(), true);
        } catch (UnknownHostException e) {
            System.err.println("Error with the host");
            return;
        } catch (IOException e) {
            System.err.println("Cannot get I/O for the connection");
            return;
        }
        System.out.println("Target Connected...");
        //---- Receive ----//
        // Bind
        ServerSocket malloryRecSocket;
        try {
            malloryRecSocket = new ServerSocket(selfportNumber);
        } catch (IOException e) {
            System.err.println("Cannot bind port...");
            return;
        }
        // Listen and Accept
        Socket clientSocket;
        try {
            clientSocket = malloryRecSocket.accept();
        } catch (IOException e) {
            System.err.println("Cannot listen and/or accept...");
            return;
        }
        System.out.println("Connected...");
        //---- Transmit ----//
        BufferedReader inputReader;
        try {
            inputReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (IOException e) {
            System.err.println("Cannot Read...");
            return;
        }

        unread_q = new LinkedList<String>();
        (new Mallory()).start();

        String inputLine;
        System.out.println ("Type Message 'Quit' to quit");
        while ((inputLine = inputReader.readLine()) != null && still_receiving) {
            System.out.println("A new message came, enqueueing");
            q_lock.lock();
            unread_q.add(inputLine);
            q_lock.unlock();
        }
        still_receiving = false;
        outputWriter.close();
        inputReader.close();
        clientSocket.close();

    }
}