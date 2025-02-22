/*********************************************************************
 Authors   : Abdulla Al-Naimi, Darrick Sanders, Jose Varela Garcia, Luis Suarez, Manuela Calle.
 Course    : CIS4951 Capstone II
 Professor : Masoud Sadjadi 
 Program Purpose/Description
Our project idea is to create an SSH Honeypot in Java. An SSH Honeypot is a network decoy deployed temporarily (typically on port 22) 
and is used to capture any data on intruders trying to connect to our network through a remote connection. 
Data includes any credentials used to log in, IP addresses, and any activity after login.

 Due Date  : 04/28/2025 
 
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
import java.util.HashMap;
import java.util.Map;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.TimeZone;

/**
 * SSH Honeypot using Apache MINA SSHD 2.10.0
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

                // User root, password abc123
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
        
        // 2) Start the web dashboard
        WebDashboard.startServer();
        
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
     * A small shell that handles some basic commands and file tree navigation.
     */
    private static class MyShell implements Command, Runnable {

        //Simulation of a static filesystem tree. We are mapping directories to directory content
        // A HashMap is a data structure with key-value pairs, like a dictionary.
        private static final Map<String, String[]> FILESYSTEM = new HashMap<>();

        static {
            // Populating 'fake' directories
            FILESYSTEM.put("/root", new String[]{"Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos"});
            FILESYSTEM.put("/root/Desktop", new String[]{"notes.txt"});
            FILESYSTEM.put("/root/Documents", new String[]{"CompanySecrets.pdf", "Project"});
            FILESYSTEM.put("/root/Documents/Project", new String[]{"README.md"});
            FILESYSTEM.put("/root/Downloads", new String[]{"Install.sh"});
            FILESYSTEM.put("/root/Music", new String[]{}); //an empty 'directory'
            FILESYSTEM.put("/root/Pictures", new String[]{});
            FILESYSTEM.put("/root/Videos", new String[]{});
        }

        // Track the 'current directory'. Start at /root.
        private String currentDirectory = "/root";

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
                // Print welcome
                writeLine("Welcome to CentOS 8!");
                writeLine("Please report any issues or missing software to Some@Company.org");

                while (running) {
                    
                    //get the appropriate shell prompt based on the current directory
                    write(getPrompt());
                    out.flush();

                    // Read line of user input with echo + backspace handling
                    String line = readLineWithEcho();
                    if (line == null) {
                        // client disconnected
                        break;
                    }
                    line = line.trim();

                    // Evaluate user input:
                    if ("exit".equalsIgnoreCase(line)) {
                        break;
                    }
                    else if (line.startsWith("cd")) {
                        logger.info("User typed: {}", line);
                        CdCommand(line);
                    } 
                    else if ("ls".equalsIgnoreCase(line)) {
                        //directory listing
                        logger.info("User typed: {}", line);
                        LsCommand();
                    } else if ("uname".equalsIgnoreCase(line)) {
                        //output of uname
                        logger.info("User typed: {}", line);
                        writeLine("Linux");
                    } else if ("uname -a".equalsIgnoreCase(line)) {
                        //output of uname -a
                        logger.info("User typed: {}", line);
                        writeLine(getUname());
                    }
                    else if ("hostname".equalsIgnoreCase(line)) {
                        logger.info("User typed: {}", line);
                        writeLine("Company");
                    }
                    else if ("whoami".equalsIgnoreCase(line)) {
                        logger.info("User typed: {}", line);
                        writeLine("root");
                    }
                    else if ("pwd".equalsIgnoreCase(line)) {
                        logger.info("User typed: {}", line);
                        writeLine(currentDirectory);
                    }
                    else if ("history".equalsIgnoreCase(line)) {
                        logger.info("User typed: {}", line);
                        writeLine("1  history");
                        //We could change this to accurately track command history.
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
        
        //get the appropriate shell prompt based on the current directory
        private String getPrompt() {
            if ("/root".equals(currentDirectory)) {
                return "root@Company:~# ";
            } else if (currentDirectory.startsWith("/root/")) {
                String subPath = currentDirectory.substring("/root".length()); //subpath is everything after "/root" in the string
                return "root@Company:~" + subPath + "# "; //prepend ~ and add # at the end.
            } else {
                return "root@Company:" + currentDirectory + "# ";
            }
        }

        //Process the cd command
        private void CdCommand(String line) throws IOException {
            String[] parts = line.split("\\s+");
            // If no argument, go to /root
            if (parts.length == 1) {
                currentDirectory = "/root";
                return;
            }
            String target = parts[1];

            // 'cd ..' => go up one directory
            if ("..".equals(target)) {
                currentDirectory = goUpOneLevel(currentDirectory);
                return;
            }
            // If user typed an absolute path
            if (target.startsWith("/")) {
                if (FILESYSTEM.containsKey(target)) {
                    currentDirectory = target;
                } else {
                    writeLine("bash: cd: " + target + ": No such file or directory");
                }
            } else {
                // If user typed a relative path, then we combine with currentDirectory
                String newPath = currentDirectory.equals("/") 
                        ? "/" + target 
                        : currentDirectory + "/" + target;
                if (FILESYSTEM.containsKey(newPath)) {
                    currentDirectory = newPath;
                } else {
                    writeLine("bash: cd: " + target + ": No such file or directory");
                }
            }
        }
        
        // Going up one level. 'cd ..'
        private String goUpOneLevel(String path) {
            // If at / or /root, don't allow going higher.
            if ("/".equals(path) || "/root".equals(path)) {
                return "/root";
            }
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash <= 0) {
                // fallback if somehow not found
                return "/root";
            }
            return path.substring(0, lastSlash);
        }
        
        //Process the ls command
        private void LsCommand() throws IOException {
            String[] items = FILESYSTEM.get(currentDirectory);
            if (items == null || items.length == 0) {
                // no items
                writeLine("");
            } else {
                // Join them with spaces
                writeLine(String.join("    ", items));
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

