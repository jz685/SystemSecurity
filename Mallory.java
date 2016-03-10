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

class MSG_NO_ENC implements Serializable{
    public String entity;
    public int msg_num;
    public String msg;

    public MSG_NO_ENC(String ent, String msg_to_send, int num_msg) {
        entity = ent;
        msg_num = num_msg;
        msg = msg_to_send;
    }
    public MSG_NO_ENC(String ent, String msg_to_send, String num_msg) {
        entity = ent;
        msg_num = Integer.parseInt(num_msg);
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
    // public KEY_TRANSPORT(String ent, String t, String encoded, String signature) {
    //     entity = ent;
    //     Timestamp timestamp;
    //     try{
    //         SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSS");
    //         Date parsedDate = dateFormat.parse(t);
    //         timestamp = new java.sql.Timestamp(parsedDate.getTime());
    //     }catch(Exception e){//this generic but you can control another types of exception
    //         System.err.println("Converting Error: " + e.toString());
    //     }
    //     ts = timestamp; 
    //     enc = encoded;
    //     // signed = signature;
    //     // Don't know how to do this...........!!!!!!!!!!!!!!!!
    // }
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
    public MSG_SYM(String ent, String encode, int num_msg, String generatedIV) {
        entity = ent;
        msg_num = num_msg;
        enc = encode.getBytes();
        theIV = generatedIV.getBytes();
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

public class Mallory extends Thread{

    public static Queue<Object> unread_q;
    public static List<Object> message_list;
    // public static PrintWriter outputWriter;
    public static ObjectOutputStream outputObject;
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
                    Object nextMessage = unread_q.remove();
                    message_list.add(nextMessage);
                    q_lock.unlock();

                    //Print message
                    String inputLine;
                    System.out.println("Showing next unread message:");
                    if (nextMessage instanceof MSG_NO_ENC) {
                        inputLine = ((MSG_NO_ENC)nextMessage).toStr();
                        System.out.println("Incoming Message: " + inputLine);
                    } else if (nextMessage instanceof KEY_TRANSPORT) {
                        inputLine = ((KEY_TRANSPORT)nextMessage).toStr();
                        System.out.println("Incoming Message: " + inputLine);
                    } else if (nextMessage instanceof MSG_SYM) {
                        inputLine = ((MSG_SYM)nextMessage).toStr();
                        System.out.println("Incoming Message: " + inputLine);
                    } else if (nextMessage instanceof MSG_MAC) {
                        inputLine = ((MSG_MAC)nextMessage).toStr();
                        System.out.println("Incoming Message: " + inputLine);
                    } else if (nextMessage instanceof MSG_SYMMAC) {
                        inputLine = ((MSG_SYMMAC)nextMessage).toStr();
                        System.out.println("Incoming Message: " + inputLine);
                    }
                    // System.out.println(nextMessage);

                    //Wait until told what to do about the message
                    boolean proper_response = false;
                    while (!proper_response) {
                        System.out.println("Type p to pass, d to delete, m to modify");
                        userInput = bufferReader.readLine(); 
                        if (userInput.equalsIgnoreCase("p")) {
                            // outputWriter.println(nextMessage);
                            outputObject.writeObject(nextMessage); 
                            proper_response = true;
                        }
                        else if (userInput.equalsIgnoreCase("d")) {
                            proper_response = true;
                        }
                        else if (userInput.equalsIgnoreCase("m")) {
                            proper_response = true;
                            // How to Modify????
                            if (nextMessage instanceof MSG_NO_ENC) {
                                MSG_NO_ENC modifyObj = ((MSG_NO_ENC)nextMessage);
                                // System.out.println("Incoming Message: " + modifyObj);
                            } else if (nextMessage instanceof KEY_TRANSPORT) {
                                KEY_TRANSPORT modifyObj = ((KEY_TRANSPORT)nextMessage);
                                // System.out.println("Incoming Message: " + modifyObj);
                            } else if (nextMessage instanceof MSG_SYM) {
                                MSG_SYM modifyObj = ((MSG_SYM)nextMessage);
                                // System.out.println("Incoming Message: " + modifyObj);
                            } else if (nextMessage instanceof MSG_MAC) {
                                MSG_MAC modifyObj = ((MSG_MAC)nextMessage);
                                // System.out.println("Incoming Message: " + modifyObj);
                            } else if (nextMessage instanceof MSG_SYMMAC) {
                                MSG_SYMMAC modifyObj = ((MSG_SYMMAC)nextMessage);
                                // System.out.println("Incoming Message: " + modifyObj);
                            }
                            System.out.println("Enter a string to pass along:");

                            userInput = bufferReader.readLine();
                            // outputWriter.println(userInput);
                            outputObject.writeObject(userInput); 
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
        message_list = new ArrayList<Object>();
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
            // outputWriter = new PrintWriter(mallorySenSocket.getOutputStream(), true);
            outputObject = new ObjectOutputStream(mallorySenSocket.getOutputStream());
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
        ObjectInputStream objInp;
        try {
            objInp = new ObjectInputStream(clientSocket.getInputStream());
            // inputReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (IOException e) {
            System.err.println("Cannot Read...");
            return;
        }

        unread_q = new LinkedList<Object>();
        (new Mallory()).start();

        String inputLine;
        System.out.println ("Type Message 'Quit' to quit");
        Object next_message;
        try {
            while ((next_message = objInp.readObject()) != null) {
            // while ((inputLine = inputReader.readLine()) != null && still_receiving) {
                // if (next_message instanceof MSG_NO_ENC) {
                //     inputLine = ((MSG_NO_ENC)next_message).toStr();
                //     // System.out.println("Incoming Message: " + inputLine);
                // } else if (next_message instanceof KEY_TRANSPORT) {
                //     inputLine = ((KEY_TRANSPORT)next_message).toStr();
                //     // System.out.println("Incoming Message: " + inputLine);
                // } else if (next_message instanceof MSG_SYM) {
                //     inputLine = ((MSG_SYM)next_message).toStr();
                //     // System.out.println("Incoming Message: " + inputLine);
                // } else if (next_message instanceof MSG_MAC) {
                //     inputLine = ((MSG_MAC)next_message).toStr();
                //     // System.out.println("Incoming Message: " + inputLine);
                // } else if (next_message instanceof MSG_SYMMAC) {
                //     inputLine = ((MSG_SYMMAC)next_message).toStr();
                //     // System.out.println("Incoming Message: " + inputLine);
                // } else {
                //     System.err.println("Unknown Type, Abort");
                //     return;
                // }

                System.out.println("A new message came, enqueueing");
                q_lock.lock();
                unread_q.add(next_message);
                q_lock.unlock();
            }
            still_receiving = false;
        } catch (Exception e) {
            System.err.println("Error Reading: " + e.toString());
        }
        outputObject.close();
        objInp.close();
        clientSocket.close();

    }
}