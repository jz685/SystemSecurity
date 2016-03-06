import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;


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

        try {
            while(still_receiving) {
                q_lock.lock();
                if (!unread_q.isEmpty()) {
                    //Get next unread message
                    String nextMessage = unread_q.remove();
                    message_list.add(nextMessage);
                    q_lock.unlock();

                    //Print message
                    System.out.println("Showing next message:");
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
                else {
                    q_lock.unlock();
                    //print out asking
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

            //System.out.println("Incoming Message: " + inputLine);
            //System.out.println("Please choose to read/modify/delete the message: ");
            //String userInput = bufferReader.readLine(); 
            
            //outputWriter.println(userInput);
            //if (inputLine == "Quit") {
            //    break;
            //}
        }
        still_receiving = false;
        outputWriter.close();
        inputReader.close();
        clientSocket.close();

    }
}