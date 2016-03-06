import java.io.*;
import java.net.*;
import java.util.*;
import Util.Helper;

public class Bob {

    public enum Encrypt_Type {
        NONE, SYM, MAC, SYMMAC
    }

    public static void main(String[] args) throws IOException{
        Encrypt_Type enc_type = Encrypt_Type.NONE;

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
        BufferedReader inputReader;
        try {
            inputReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (IOException e) {
            System.err.println("Cannot Read...");
            return;
        }
        int msg_index = 0;
        String inputLine;
        while ((inputLine = inputReader.readLine()) != null) {
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
        }
        inputReader.close();
        clientSocket.close();
    }
}