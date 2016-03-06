import java.io.*;
import java.net.*;
import java.util.*;

public class Alice {

    public static void main(String[] args) throws IOException{
        // Accepting portNummber that is less than Integer.MAX_VALUE
        int portNumber = 2000;
        InetAddress localIP = InetAddress.getLocalHost();
        if (args == null || args.length < 1) {
        } else if (args.length == 1) {
            portNumber = Integer.parseInt(args[0]);
        } else if (args.length > 2) {
            System.err.println("Command Error, Format: $ java Alice <port number> <IP address>");
            return;
        } else {
            try {
                portNumber = Integer.parseInt(args[0]);
                localIP = InetAddress.getByName(args[1]);
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
        System.out.println ("Type Message 'Quit' to quit");
        while ((userInput = bufferReader.readLine()) != null) {
            outputWriter.println(userInput);
            if (userInput.equals("Quit")) {
                break;
            }
        }
        outputWriter.close();
        bufferReader.close();
        aliceSocket.close();
    }
}