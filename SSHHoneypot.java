/*********************************************************************
 Authors   : Abdulla Al-Naimi, Darrick Sanders, John Espinal, Manuela Calle, Luis Suarez
 Course    : CIS3950 Capstone I
 Professor : Masoud Sadjadi 
 Program Purpose/Description
Our project idea is to create an SSH Honeypot. SSH Honeypot is a network decoy deployed temporarily on port 22 
and is used to capture any data on intruders trying to connect to our network through a remote connection. 
Data includes any credentials used to log in, IP addresses, and any activity after login.

 Due Date  : 12/07/2024 
 
*********************************************************************/

import java.io.*;
import java.net.*;

public class SSHHoneypot
{
    private static void handleClient(Socket clientSocket)
    {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true))
        {
            
            out.println("Welcome to FIU SSH honeypot. Please enter your username:");
            String username = in.readLine();
            
            out.println("Password for user " + username + ":");
            String password = in.readLine();
            
            out.println("Login failed: incorrect username or password.");
            
        } 
        catch (IOException e)
        {
            e.printStackTrace();
        } 
        finally
        {
            try
            {
                clientSocket.close();
            } 
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args)
    {
        int port = 2224; // You might need to use a different port for testing.
        try (ServerSocket serverSocket = new ServerSocket(port))
        {
            System.out.println("Listening for connections on port " + port);
            
            while (true)
            {
                Socket clientSocket = serverSocket.accept();
                handleClient(clientSocket);
            }
        } 
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }
}
