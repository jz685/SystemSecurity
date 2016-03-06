import java.io.*;
import java.net.*;
import java.util.*;
import Util.Helper;

public class Bob {

    public static void main(String[] args) throws IOException{
        // Accepting portNummber that is less than Integer.MAX_VALUE
        int portNumber = 3000;
        if (args == null || args.length == 0) {
            // Nothing, using default value
        } else if (args.length > 1) {
            System.err.println("Command Error, Format: $ java Bob <port number>");
            return;
        } else {
            portNumber = Integer.parseInt(args[0]);
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
            // PrintWriter outputWriter = new PrintWriter(clientSocket.getOutputStream(), true); // true for auto-flush
            inputReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (IOException e) {
            System.err.println("Cannot Read...");
            return;
        }
        String inputLine;
        while ((inputLine = inputReader.readLine()) != null) {
            System.out.println("Incoming Message: " + inputLine);
            if (inputLine == "Quit") {
                break;
            }
        }
        // outputWriter.close();
        inputReader.close();
        clientSocket.close();
    }
}