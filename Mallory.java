import java.io.*;
import java.net.*;
import java.util.*;

public class Mallory {

    public static void main(String[] args) throws IOException{
        // Accepting portNummber that is less than Integer.MAX_VALUE
        int selfportNumber = 2000;
        InetAddress selflocalIP = InetAddress.getLocalHost();
        int targetportNumber = 3000;
        InetAddress targetlocalIP = InetAddress.getLocalHost();
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
        PrintWriter outputWriter;
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
        String inputLine;
        BufferedReader bufferReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println ("Type Message 'Quit' to quit");
        while ((inputLine = inputReader.readLine()) != null) {
            System.out.println("Incoming Message: " + inputLine);
            System.out.println("Please choose to read/modify/delete the message: ");
            String userInput = bufferReader.readLine()); 
            
            outputWriter.println(inputLine);
            if (inputLine == "Quit") {
                break;
            }
        }
        outputWriter.close();
        inputReader.close();
        clientSocket.close();

    }
}