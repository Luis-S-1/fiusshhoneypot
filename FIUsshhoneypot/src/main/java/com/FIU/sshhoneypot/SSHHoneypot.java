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

//The following are for implementing the cat command.
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * SSH Honeypot using Apache MINA SSHD 2.10.0
 */
public class SSHHoneypot {

    private static final Logger logger = LoggerFactory.getLogger(SSHHoneypot.class);
    
    // Real directory storing files for the honeypot intruder
    private static final String HONEYFILES_DIR = "src/main/java/com/FIU/sshhoneypot/honeyfiles";


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
            
            //populating filesystem root directory: 
            FILESYSTEM.put("/", new String[]{"bin", "dev", "home", "lib64", "mnt", "proc", "root", "tmp", "usr", "var", "boot", "etc", "lib", "media", "opt", "sbin", "sys"});
            FILESYSTEM.put("/bin", new String[]{});
            FILESYSTEM.put("/dev", new String[]{});
            FILESYSTEM.put("/home", new String[]{});
            FILESYSTEM.put("/lib64", new String[]{});
            FILESYSTEM.put("/mnt", new String[]{});
            FILESYSTEM.put("/proc", new String[]{});
            FILESYSTEM.put("/tmp", new String[]{});
            FILESYSTEM.put("/usr", new String[]{});
            FILESYSTEM.put("/var", new String[]{});
            FILESYSTEM.put("/boot", new String[]{"config-4.18.0-348.el8.x86_64","efi","grub2","initramfs-0-rescue-fbfbc8aac4d04623a96a8dc43deea6ce.img","initramfs-4.18.0-348.el8.x86_64.img","initramfs-4.18.0-348.el8.x86_64kdump.img","loader","symvers-4.18.0-348.el8.x86_64.gz","System.map-4.18.0-348.el8.x86_64","vmlinuz-0-rescue-fbfbc8aac4d04623a96a8dc43deea6ce","vmlinuz-4.18.0-348.el8.x86_64"});
            FILESYSTEM.put("/etc", new String[]{});
            FILESYSTEM.put("/lib", new String[]{});
            FILESYSTEM.put("/media", new String[]{});
            FILESYSTEM.put("/opt", new String[]{});
            FILESYSTEM.put("/sbin", new String[]{});
            FILESYSTEM.put("/sys", new String[]{});
            
            //populating some of the filesystem root subdirectories:
            FILESYSTEM.put("/boot/efi", new String[]{});
            FILESYSTEM.put("/boot/grub2", new String[]{});
            FILESYSTEM.put("/boot/loader", new String[]{});
            //populating root user home directory:
            FILESYSTEM.put("/root", new String[]{"Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos"});
            FILESYSTEM.put("/root/Desktop", new String[]{"notes.txt"});
            FILESYSTEM.put("/root/Documents", new String[]{"CompanySecrets.pdf", "Project", "secrets_readme.txt"});
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
                    // Print welcome banner
                    printBanner();

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
                        else if ("id".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine("uid=0(root) gid=0(root) groups=0(root)");
                        }
                        else if ("ps".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine("PID TTY          TIME CMD");
                            writeLine("945 pts/0    00:00:00 bash");
                            writeLine("002 pts/0    00:00:00 ps");
                        }
                        else if ("ps -ef".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine("UID          PID    PPID  C STIME TTY          TIME CMD");
                            writeLine("root           1       0  0 03:00 ?        00:00:51 systemd");
                            writeLine("root         502       1  0 03:00 ?        00:00:00 systemd-journald");
                            writeLine("root         534       1  0 03:00 ?        00:00:00 systemd-udevd");
                            writeLine("root         705       1  0 03:00 ?        00:00:00 NetworkManager");
                            writeLine("root         712       1  0 03:00 ?        00:00:00 firewalld");
                            writeLine("root         745       1  0 03:00 ?        00:00:02 fail2ban-server --execstart /usr/bin/fail2ban-server");
                            writeLine("root         810       1  0 03:00 ?        00:00:01 wazuh-agent");
                            writeLine("root         811       1  0 03:00 ?        00:00:02 suricata -c /etc/suricata/suricata.yaml -D");
                            writeLine("root         945     811  0 03:10 pts/0    00:00:00 bash");
                            writeLine("root         002     945  0 03:11 pts/0    00:00:00 ps");
                        }
                        else if ("cat secrets_readme.txt".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            
                            String fileName = HONEYFILES_DIR+"/secrets_readme.txt"; //path to the text file
                            
                            if(currentDirectory.equals("/root/Documents")) {
                                try (FileReader fileReader = new FileReader(fileName); BufferedReader br = new BufferedReader(fileReader))
                                {
                                String lineOfTextFile;
                                //We read the text file line by line. readLine() returns null when it reaches the end of the file
                                    while ((lineOfTextFile = br.readLine()) != null) 
                                    {
                                        writeLine(lineOfTextFile); //display to screen
                                    }
                                } 
                                catch (IOException e) 
                                {
                                    e.printStackTrace();
                                }
                            
                            }
                            else{
                                    writeLine("cat: secrets_readme.txt: No such file or directory");
                                }
                            
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
            
            // the root / path is the highest level:
            if ("/".equals(path)) {
                return "/";
            }

            // Otherwise, find the last slash
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash <= 0) {
                // If somehow not found, go to /
                return "/";
            }
            //return the path for the level above the current one:
            return path.substring(0, lastSlash); 
        }

        
        //Process the ls command
        //This is a simpler version of LsCommand() to fall back to if needed:
        /*private void LsCommand() throws IOException {
            String[] items = FILESYSTEM.get(currentDirectory);
            if (items == null || items.length == 0) {
                // no items
                writeLine("");
            } else {
                // Join them with spaces
                writeLine(String.join("    ", items));
            }
        } */
        
        //better version of LsCommand() that attempts to print in a more organized manner, with columns.
        private void LsCommand() throws IOException {
            String[] items = FILESYSTEM.get(currentDirectory);
            if (items == null || items.length == 0) {
                writeLine("");
                return;
            }

            // 1) Find the widest item
            int maxLen = 0;
            for (String item : items) {
                if (item.length() > maxLen) {
                    maxLen = item.length();
                }
            }

            // 2) Add some spacing
            // so "Column width" = widest-item-length + 3 spaces
            int colWidth = maxLen + 3;

            // 3) Find how many columns fit in 80 chars, minimum of 1
            int screenWidth = 80;
            int numColumns = Math.max(1, screenWidth / colWidth);

            // 4) Print items in columns
            StringBuilder line = new StringBuilder();
            int count = 0;
            for (int i = 0; i < items.length; i++) {
                // Left-align the item within colWidth
                line.append(String.format("%-" + colWidth + "s", items[i]));
                count++;

                // If we’ve filled a row or hit the end, output that row
                if (count == numColumns || i == items.length - 1) {
                    writeLine(line.toString());
                    line.setLength(0);
                    count = 0;
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

        //print the welcome banner:
        private void printBanner() throws IOException{
                
                writeLine("***************************************************************");
                writeLine("*                                                             *");
                writeLine("*                    **** NOTICE ****                         *");
                writeLine("*                                                             *");
                writeLine("***************************************************************");
                writeLine("     /\\");
                writeLine("    /  \\");
                writeLine("   /____\\");
                writeLine("  /\\    /\\");
                writeLine(" /  \\  /  \\");
                writeLine("/____\\/____\\");
                writeLine("");
                writeLine("Welcome to the Palisade Bank Corporation secure access system.");
                writeLine("This system is for use by authorized personnel only. Unauthorized");
                writeLine("access or use of this system is strictly prohibited and may lead");
                writeLine("to legal consequences, including prosecution under applicable laws.");
                writeLine("");
                writeLine("All activities on this system are subject to monitoring, logging,");
                writeLine("and auditing. By continuing, you acknowledge that you have no");
                writeLine("expectation of privacy while using this system. Any evidence of");
                writeLine("unauthorized access or misuse will be reported to security");
                writeLine("personnel and law enforcement authorities.");
                writeLine("");
                writeLine("If you do not agree to these terms, please log off immediately.");
                writeLine("");
                writeLine("***************************************************************");
                writeLine("");
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

