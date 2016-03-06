import java.io.*;
import java.net.*;
import java.util.*;

public class Alice {

    public enum Encrypt_Type {
        NONE, SYM, MAC, SYMMAC
    }

    public static void main(String[] args) throws IOException{
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