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

package com.FIU.sshhoneypot;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.common.SshConstants;

import java.io.IOException;

public class SSHHoneypot
{ 
    //In the future, to allow more than one attempt, we can use these two variables:
    //private static final int MAX_ATTEMPTS = 3; // Change this to your desired number of attempts
    //private final AtomicInteger attemptCounter = new AtomicInteger(0);

    public static void main(String[] args) throws IOException
    {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(2224);  // Set the port to 2224
        
        // Set up a simple key provider
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());

        // Implement password authenticator (fake credentials)
        sshd.setPasswordAuthenticator(new PasswordAuthenticator()
        {
            @Override
            public boolean authenticate(String username, String password, ServerSession session)
            {
                System.out.println("Login attempt with username: " + username + " and password: " + password);
                
                 try
                 {
                     // Disconnect the session with a reason and message
                     session.disconnect(SshConstants.SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER, "Permission denied, please try again.");
                 } 
                 catch (IOException e)
                 {
                     System.err.println("Failed to disconnect session: " + e.getMessage());
                 }
                
                
                return false;  // Always fail login for honeypot purposes
            }
        });

        // Start the SSH server
        sshd.start();
        System.out.println("SSH Honeypot listening on port 2224...");
        
    // Keep the main thread alive to avoid exit
        try
        {
            // Keep the server running until interrupted
            Thread.currentThread().join();
        } 
        catch (InterruptedException e) 
        {
            // Handle interruption (e.g., server shutdown)
            System.out.println("Server interrupted, shutting down...");
        }
        finally
        {
            sshd.stop(); // Ensure the server is stopped when exiting
        }
    
    }
}
