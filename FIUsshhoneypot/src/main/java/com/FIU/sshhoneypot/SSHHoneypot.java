/*********************************************************************
 Authors   : Abdulla Al-Naimi, Darrick Sanders, Jose Varela Garcia, Luis Suarez, Manuela Calle.
 Course    : CIS3950 Capstone I
 Professor : Masoud Sadjadi 
 Program Purpose/Description
Our project idea is to create an SSH Honeypot. SSH Honeypot is a network decoy deployed temporarily (typically on port 22) 
and is used to capture any data on intruders trying to connect to our network through a remote connection. 
Data includes any credentials used to log in, IP addresses, and any activity after login.

 Due Date  : 12/16/2024 
 
*********************************************************************/

package com.FIU.sshhoneypot;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Minimal SSH Honeypot using Apache MINA SSHD 2.10.x with echo, Enter, and Backspace support.
 */
public class SSHHoneypot {

    private static final Logger logger = LoggerFactory.getLogger(SSHHoneypot.class);

    // Max login attempts
    private static final int MAX_ATTEMPTS = 3;

    // Tracks the number of login attempts
    private static final AtomicInteger attemptCounter = new AtomicInteger(0);

    public static void main(String[] args) throws IOException {
        // Set up the SSH server
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(2224);  // Listening port
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());

        // Password Authenticator
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session) {
                int attempts = attemptCounter.incrementAndGet();

                // Get client IP address
                SocketAddress remoteAddress = session.getClientAddress();
                String clientIP = (remoteAddress != null) ? remoteAddress.toString() : "Unknown-IP";

                // Log the login attempt
                System.out.println("Login attempt #" + attempts + " from IP: " + clientIP
                        + " with username: " + username + " and password: " + password);
                logger.info("Login attempt #" + attempts + " from IP: " + clientIP
                        + " with username: " + username + " and password: " + password);

                // If the max attempts are reached, disconnect
                if (attempts >= MAX_ATTEMPTS) {
                    try {
                        session.disconnect(SshConstants.SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER,
                                "Too many failed login attempts.");
                        logger.info("Session disconnected after " + attempts + " failed attempts.");
                    } catch (IOException e) {
                        logger.error("Failed to disconnect session: " + e.getMessage());
                    }
                    return false;
                }

                // Allow only username = "luis" and password = "a"
                if ("root".equals(username) && "abc123".equals(password)) {
                    // Reset counter on success
                    attemptCounter.set(0);
                    return true;
                }

                // Otherwise, deny
                return false;
            }
        });

        // Use our custom ShellFactory instead of a CommandFactory
        sshd.setShellFactory(new MyShellFactory());

        // Start the SSH server
        sshd.start();
        System.out.println("SSH Honeypot listening on port 2224...");
        logger.info("SSH Honeypot listening on port 2224...");

        // Keep running
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            System.out.println("Server interrupted, shutting down...");
            logger.info("Server interrupted, shutting down...");
        } finally {
            sshd.stop();
            logger.info("SSH server stopped.");
        }
    }

    /**
     * Our ShellFactory that creates a new MyShell instance for each session.
     */
    private static class MyShellFactory implements ShellFactory {
        @Override
        public Command createShell(ChannelSession channel) throws IOException {
            return new MyShell();
        }
    }

    /**
     * A minimal shell that echoes user input and handles 'ls', 'exit', and unknown commands.
     */
    private static class MyShell implements Command, Runnable {

        private InputStream in;
        private OutputStream out;
        private OutputStream err;
        private ExitCallback exitCallback;
        @SuppressWarnings("unused")
        private Environment environment;
        private Thread thread;
        private volatile boolean running = false;

        @Override
        public void setInputStream(InputStream in) {
            this.in = in;
        }

        @Override
        public void setOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void setErrorStream(OutputStream err) {
            this.err = err;
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
            this.exitCallback = callback;
        }

        @Override
        public void start(ChannelSession channel, Environment env) throws IOException {
            this.environment = env;
            running = true;
            thread = new Thread(this, "MyShell-Thread");
            thread.start();
        }

        @Override
        public void destroy(ChannelSession channel) throws IOException {
            running = false;
            if (thread != null) {
                thread.interrupt();
                thread = null;
            }
        }

        @Override
        public void run() {
            try {
                // Print welcome once
                writeLine("Welcome to CentOS 8!");
                writeLine("Please report any issues or missing software to Some@Company.org");
                //writeLine("Type 'ls' to 'list directory contents', or 'exit' to quit.");

                while (running) {
                    // Print prompt
                    write("root@Company:~# ");
                    out.flush();

                    // Read line of user input with echo + backspace handling
                    String line = readLineWithEcho();
                    if (line == null) {
                        // client disconnected
                        break;
                    }
                    line = line.trim();

                    // Check commands
                    if ("exit".equalsIgnoreCase(line)) {
                        break;
                    } else if ("ls".equalsIgnoreCase(line)) {
                        //directory listing
                        writeLine("file1.txt");
                        writeLine("file2.log");
                        writeLine("Documents");
                    } else if ("uname".equalsIgnoreCase(line)) {
                        //output of uname
                        writeLine("Linux");
                    } else if ("uname -a".equalsIgnoreCase(line)) {
                        //output of uname -a
                        writeLine(getUname());
                    } 
                    else if (!line.isEmpty()) {
                        logger.info("User typed command: {}", line);
                        writeLine("bash: " + line + ": command not found");
                    }
                }

            } catch (IOException e) {
                logger.error("IOException in shell: " + e.getMessage());
            } finally {
                if (exitCallback != null) {
                    exitCallback.onExit(0);
                }
            }
        }

        /**
         * Reads a line from the user, echoing each character and handling backspace.
         * Returns null if the stream closes (client disconnected).
         */
        private String readLineWithEcho() throws IOException {
            StringBuilder sb = new StringBuilder();
            while (true) {
                int ch = in.read();
                if (ch == -1) {
                    // End of stream
                    return null;
                }

                // Handle Enter
                if (ch == '\n' || ch == '\r') {
                    // Some clients send \r, some send \n, or \r\n
                    // We'll treat both as "Enter"
                    write("\r\n"); // Echo newline
                    break;
                }
                // Handle backspace (ASCII 8 or 127)
                else if (ch == 8 || ch == 127) {
                    if (sb.length() > 0) {
                        sb.deleteCharAt(sb.length() - 1);
                        // Move cursor back one, overwrite with space, move back again
                        write("\b \b");
                    }
                }
                else {
                    // Echo typed character
                    out.write(ch);
                    out.flush();

                    // Add to our input buffer
                    sb.append((char) ch);
                }
            }
            return sb.toString();
        }

        // Helper methods to write to output
        private void writeLine(String msg) throws IOException {
            write(msg + "\r\n");
        }

        private void write(String msg) throws IOException {
            if (out != null) {
                out.write(msg.getBytes());
                out.flush();
            }
        }
        
        private String getUname() {
        // Define system properties
        String hostname = "Company";
        String kernelVersion = "4.18.0-553.33.1.el8_10.x86_64";
        String arch = "x86_64 x86_64 x86_64 GNU/Linux";

        // Get current date in the expected format for uname command
        ZonedDateTime now = ZonedDateTime.now(TimeZone.getTimeZone("EST").toZoneId());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
        String formattedDate = now.format(formatter);

        // Construct uname -a output
        return String.format("Linux %s %s #1 SMP %s %s", hostname, kernelVersion, formattedDate, arch);
		}
    }
}

