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
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.TimeZone;

/**
 * We use the Apache MINA SSHD 2.10.0 library to create an SSH server.
 */
public class SSHHoneypot {

    private static final Logger logger = LoggerFactory.getLogger(SSHHoneypot.class);
    
    // Project directory storing various files for the honeypot
    private static final String HONEYFILES_DIR = "src/main/java/com/FIU/sshhoneypot/honeyfiles";
    
    private static final String HISTORY_FILE_NAME = "history.txt";  // name of the file in honeyfiles directory
    private static final int HISTORY_LIMIT = 1000;                  // history contains 1000 entries max.

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
     * ShellFactory creates a new MyShell instance for each session.
     */
    private static class MyShellFactory implements ShellFactory {
        @Override
        public Command createShell(ChannelSession channel) throws IOException {
            return new MyShell();
        }
    }

    /**
     * The custom shell:
     */
    private static class MyShell implements Command, Runnable {

        /**
         * Simulation of a static filesystem tree. Directories are mapped to lists
         * containing their contents (file and subdirectory names).
         */
        private static final Map<String, List<String>> FILESYSTEM = new HashMap<>();
        
        //to construct a fake 'uptime':
        private static final long bootTimeMillis = System.currentTimeMillis() - getFakeUptimeMillis();


        static {
            // Populate the fake root directory with default Centos 8 Linux subdirectories/files
            FILESYSTEM.put("/", new ArrayList<>(Arrays.asList(
                    "bin", "dev", "home", "lib64", "mnt", "proc", "root", "tmp",
                    "usr", "var", "boot", "etc", "lib", "media", "opt", "sbin", "sys"
            )));

            // Populate fake directories by reading from text files.
            populateDirByFileRead("/bin", "bin.txt");
            populateDirByFileRead("/dev", "dev.txt");
            FILESYSTEM.put("/home", new ArrayList<>()); // example of an empty fake directory
            populateDirByFileRead("/lib64", "lib64.txt");
            FILESYSTEM.put("/mnt", new ArrayList<>());
            populateDirByFileRead("/proc", "proc.txt");
            populateDirByFileRead("/tmp", "tmp.txt");
            populateDirByFileRead("/usr", "usr.txt");
            populateDirByFileRead("/var", "var.txt");

            FILESYSTEM.put("/boot", new ArrayList<>(Arrays.asList(
                    "config-4.18.0-348.el8.x86_64","efi","grub2",
                    "initramfs-0-rescue-fbfbc8aac4d04623a96a8dc43deea6ce.img",
                    "initramfs-4.18.0-348.el8.x86_64.img",
                    "initramfs-4.18.0-348.el8.x86_64kdump.img",
                    "loader","symvers-4.18.0-348.el8.x86_64.gz",
                    "System.map-4.18.0-348.el8.x86_64",
                    "vmlinuz-0-rescue-fbfbc8aac4d04623a96a8dc43deea6ce",
                    "vmlinuz-4.18.0-348.el8.x86_64"
            )));
            populateDirByFileRead("/etc", "etc.txt");
            populateDirByFileRead("/lib", "lib.txt");
            FILESYSTEM.put("/media", new ArrayList<>());
            FILESYSTEM.put("/opt", new ArrayList<>());
            populateDirByFileRead("/sbin", "sbin.txt");
            populateDirByFileRead("/sys", "sys.txt");

            // Some subdirectories under /boot
            FILESYSTEM.put("/boot/efi", new ArrayList<>());
            FILESYSTEM.put("/boot/grub2", new ArrayList<>());
            FILESYSTEM.put("/boot/loader", new ArrayList<>());

            // root user home directory and subdirectories
            FILESYSTEM.put("/root", new ArrayList<>(Arrays.asList(
                    "Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos"
            )));
            FILESYSTEM.put("/root/Desktop", new ArrayList<>(Collections.singletonList("notes.txt")));
            FILESYSTEM.put("/root/Documents", new ArrayList<>(Arrays.asList("CompanySecrets.pdf", "Project", "secrets_readme.txt")));
            FILESYSTEM.put("/root/Documents/Project", new ArrayList<>(Collections.singletonList("README.md")));
            FILESYSTEM.put("/root/Downloads", new ArrayList<>(Collections.singletonList("Install.sh")));
            FILESYSTEM.put("/root/Music", new ArrayList<>());
            FILESYSTEM.put("/root/Pictures", new ArrayList<>());
            FILESYSTEM.put("/root/Videos", new ArrayList<>());
        }

        // Track the 'current working directory'. Start at /root.
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
                    // Print shell prompt
                    write(getPrompt());
                    out.flush();

                    // Read line of user input
                    String line = readLineWithEcho();
                    if (line == null) {
                        // client disconnected
                        break;
                    }
                    line = line.trim();
                    if (line.isEmpty()) {
                        continue;
                    }

                    //logic for history command:
                    if (line.startsWith("history")) {
                        logger.info("User typed: {}", line);
                        if ("history -c".equals(line)) {
                            // Clear the history file
                            clearHistory();
                        } else if ("history".equals(line)) {
                            historyCommand();  
                        } else {
                            historyCommand();
                        }
                    }
                    else { //logic for all other commands:

                        //record the line in history.txt
                        recordCommand(line);
                        
                        // Evaluate user input:
                        if ("exit".equalsIgnoreCase(line)) {
                            break;
                        }
                        else if (line.startsWith("cd")) {
                            logger.info("User typed: {}", line);
                            CdCommand(line);
                        }
                        else if ("ls".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            LsCommand();
                        }
                        else if ("uname".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine("Linux");
                        } 
                        else if ("uname -a".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine(getUname());
                        }
                        else if ("hostname".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine("pbc-svr04");
                        }
                        else if ("whoami".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine("root");
                        }
                        else if ("pwd".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            writeLine(currentDirectory);
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
                        else if ("date".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            printDate();
                        }
                        else if (line.startsWith("cat ")) {
                            logger.info("User typed: {}", line);
                            CatCommand(line);
                        }
                        else if ("netstat".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            printFile("netstat.txt");
                        }
                        else if (line.startsWith("mkdir ")) {
                            logger.info("User typed: {}", line);
                            mkdirCommand(line);
                        }
                        else if (line.startsWith("touch ")) {
                            logger.info("User typed: {}", line);
                            touchCommand(line);
                        }
                        else if ("df".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            printFile("df.txt");
                        }
                        else if ("df -h".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            printFile("df_h.txt");
                        }
                        else if ("ssh".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            printFile("ssh.txt");
                        }
                        else if (line.startsWith("ssh ")) {
                            logger.info("User typed: {}", line);
                            sshCommand(line);
                        }
                        else if ("ifconfig".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            printFile("ifconfig.txt");
                        }
                        else if ("uptime".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            printUptime();
                        }
                        else if (line.startsWith("ping ")) {
                            logger.info("User typed: {}", line);
                            simulatePing(line);
                        }
                        else if (line.startsWith("wget ")) {
                            logger.info("User typed: {}", line);
                            WgetCommand(line);
                        }
                        //clear the screen:
                        else if ("clear".equalsIgnoreCase(line)) {
                            logger.info("User typed: {}", line);
                            // Clear the screen using ANSI escape codes
                            write("\033[H\033[2J");
                            out.flush();
                        }
                        // if user entered unknown command:
                        else {
                            logger.info("User typed command: {}", line);
                            writeLine("bash: " + line + ": command not found");
                        }
                    }// close logic for all other commands
                }
            } catch (IOException e) {
                logger.error("IOException in shell: " + e.getMessage());
            } finally {
                if (exitCallback != null) {
                    exitCallback.onExit(0);
                }
            }
        }

    // Helper functions:
        
        
    //   ***helper functions for history command:***
    /**
     * Prints the history file, then appends a new line with the next index and
     * the word "history". (So that the user sees that new line appear at the end.)
     */
    private void historyCommand() throws IOException {
        // Read existing lines from history.txt
        List<String> lines = loadHistory();

        // Find the next index
        int lastIndex = 0;
        if (!lines.isEmpty()) {
            // for the final line's index:
            String lastLine = lines.get(lines.size() - 1);
            int space = lastLine.indexOf(' ');
            if (space > 0) {
                String idxStr = lastLine.substring(0, space);
                lastIndex = Integer.parseInt(idxStr);
            }
        }
        int nextIndex = lastIndex + 1;

        // Append the new line:
        lines.add(nextIndex + " history");
        
        // Limit is 1000 lines:
        while (lines.size() > HISTORY_LIMIT) {
            lines.remove(0);
        }

        // write updated lines to history.txt
        saveHistory(lines);

        // print lines
        for (String entry : lines) {
            writeLine(entry);
        }
    }

    /**
     * Record any command other than history
     */
    private void recordCommand(String userCommand) throws IOException {
        if (userCommand == null || userCommand.isEmpty()) {
            return;
        }

        List<String> lines = loadHistory();
        int lastIndex = 0;
        if (!lines.isEmpty()) {
            String lastLine = lines.get(lines.size() - 1);
            int space = lastLine.indexOf(' ');
            if (space > 0) {
                String idxStr = lastLine.substring(0, space);
                lastIndex = Integer.parseInt(idxStr);
            }
        }
        int nextIndex = lastIndex + 1;

        // Add new line
        lines.add(nextIndex + " " + userCommand);

        // limit is 1000
        while (lines.size() > HISTORY_LIMIT) {
            lines.remove(0);
        }
        saveHistory(lines);
    }

    /**
     *  'history -c' deletes the history
     */
    private void clearHistory() throws IOException {
        
        List<String> emptyList = new ArrayList<>();
        saveHistory(emptyList);
    }

    /**
     * Load the entire history from history.txt, returning it as a List of lines.
     */
    private List<String> loadHistory() {
        List<String> lines = new ArrayList<>();
        File histFile = new File(HONEYFILES_DIR, HISTORY_FILE_NAME);
        if (!histFile.exists()) {
            
            return lines;
        }
        try (BufferedReader br = new BufferedReader(new FileReader(histFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            
            logger.error("Error reading history file: " + e.getMessage());
        }
        return lines;
    }

    /**
     *  write history.txt with given lines
     */
    private void saveHistory(List<String> lines) {
        File histFile = new File(HONEYFILES_DIR, HISTORY_FILE_NAME);
        try (PrintWriter pw = new PrintWriter(new FileWriter(histFile, false))) {
            for (String line : lines) {
                pw.println(line);
            }
            pw.flush();
        } catch (IOException e) {
            logger.error("Error writing history file: " + e.getMessage());
        }
    }
    
    //end ***helper functions for history command***

        // "cd" command
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
                // If user typed a relative path, combine with currentDirectory
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

        // "ls" command
        private void LsCommand() throws IOException {
            List<String> items = FILESYSTEM.get(currentDirectory);
            if (items == null || items.isEmpty()) {
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

            // 2) Add spacing
            int colWidth = maxLen + 3;
            int screenWidth = 80;
            int numColumns = Math.max(1, screenWidth / colWidth);

            // 3) Print items in columns
            StringBuilder line = new StringBuilder();
            int count = 0;
            for (int i = 0; i < items.size(); i++) {
                line.append(String.format("%-" + colWidth + "s", items.get(i)));
                count++;
                if (count == numColumns || i == items.size() - 1) {
                    writeLine(line.toString());
                    line.setLength(0);
                    count = 0;
                }
            }
        }

        // "cat" command
        private void CatCommand(String line) throws IOException {
            String[] parts = line.split("\\s+", 2);
            if (parts.length < 2) {
                writeLine("cat: missing operand");
                return;
            }

            String target = parts[1]; // this should be the file name.

            // Resolve target as absolute or relative path.
            String resolvedPath;
            if (target.startsWith("/")) {
                resolvedPath = target; 
            } else {
                resolvedPath = currentDirectory.equals("/")
                    ? "/" + target
                    : currentDirectory + "/" + target;
            }

            // Figure out the parent directory of resolvedPath
            int lastSlash = resolvedPath.lastIndexOf('/');
            if (lastSlash < 0) {
                writeLine("cat: " + target + ": No such file or directory");
                return;
            }

            String parentPath = resolvedPath.substring(0, lastSlash);
            if (parentPath.isEmpty()) {
                parentPath = "/";
            }
            String itemName = resolvedPath.substring(lastSlash + 1);
            if (itemName.isEmpty()) {
                writeLine("cat: " + target + ": No such file or directory");
                return;
            }

            List<String> contents = FILESYSTEM.get(parentPath);
            if (contents == null) {
                writeLine("cat: " + target + ": No such file or directory");
                return;
            }

            // check if itemName is in parent's contents
            boolean found = false;
            for (String c : contents) {
                if (c.equals(itemName)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                writeLine("cat: " + itemName + ": No such file or directory");
                return;
            }

            // If the path is in FILESYSTEM, it's a directory
            if (FILESYSTEM.containsKey(resolvedPath)) {
                writeLine("cat: " + itemName + ": Is a directory");
                return;
            }

            // It's presumably a file. Read from the real file in honeyfiles:
            String realFilePath = HONEYFILES_DIR + "/" + itemName;
            File realFile = new File(realFilePath);
            if (!realFile.exists()) {
                // The file is not found in honeyfiles directory
                writeLine("cat: " + itemName + ": No such file or directory");
                return;
            }

            // Print the file
            printFile(itemName);
        }

        // "mkdir" command
        private void mkdirCommand(String line) throws IOException {
            String[] parts = line.split("\\s+");
            if (parts.length < 2) {
                writeLine("mkdir: missing operand");
                return;
            }
            String target = parts[1];

            // Resolve path
            String newPath;
            if (target.startsWith("/")) {
                newPath = target;
            } else {
                // relative
                newPath = currentDirectory.equals("/")
                        ? "/" + target
                        : currentDirectory + "/" + target;
            }

            // find parent
            int lastSlash = newPath.lastIndexOf('/');
            if (lastSlash < 0) {
                writeLine("mkdir: cannot create directory '" + target + "': Invalid path");
                return;
            }

            String parentPath = newPath.substring(0, lastSlash);
            if (parentPath.isEmpty()) {
                parentPath = "/";
            }
            String dirName = newPath.substring(lastSlash + 1);

            // parent must exist and must be a directory in FILESYSTEM
            if (!FILESYSTEM.containsKey(parentPath)) {
                writeLine("mkdir: cannot create directory '" + dirName + "': No such file or directory");
                return;
            }

            // Check if an item with that name already exists in parent
            List<String> parentContents = FILESYSTEM.get(parentPath);
            if (parentContents.contains(dirName)) {
                writeLine("mkdir: cannot create directory '" + dirName + "': File exists");
                return;
            }

            // Add the new directory to parent's contents
            parentContents.add(dirName);
            // Make a new entry in FILESYSTEM for that directory
            FILESYSTEM.put(newPath, new ArrayList<>());
        }

        // "touch" command
        private void touchCommand(String line) throws IOException {
            String[] parts = line.split("\\s+");
            if (parts.length < 2) {
                writeLine("touch: missing operand");
                return;
            }
            String target = parts[1];

            // Resolve path
            String newPath;
            if (target.startsWith("/")) {
                newPath = target;
            } else {
                newPath = currentDirectory.equals("/")
                        ? "/" + target
                        : currentDirectory + "/" + target;
            }

            // figure out parent
            int lastSlash = newPath.lastIndexOf('/');
            if (lastSlash < 0) {
                writeLine("touch: cannot touch '" + target + "': Invalid path");
                return;
            }

            String parentPath = newPath.substring(0, lastSlash);
            if (parentPath.isEmpty()) {
                parentPath = "/";
            }
            String fileName = newPath.substring(lastSlash + 1);

            if (!FILESYSTEM.containsKey(parentPath)) {
                writeLine("touch: cannot touch '" + fileName + "': No such directory");
                return;
            }

            // see if parent contents already has this item
            List<String> parentContents = FILESYSTEM.get(parentPath);
            if (!parentContents.contains(fileName)) {
                // add the new file name
                parentContents.add(fileName);
            }
            // if it already exists, do nothing.

            // Physically create the file in honeyfiles directory if it doesn't exist
            File realFile = new File(HONEYFILES_DIR, fileName);
            if (!realFile.exists()) {
                try {
                    if (!realFile.createNewFile()) {
                        // createNewFile returns false if the file already existed
                        // But we already checked that, so this is a fallback
                        writeLine("touch: cannot touch '" + fileName + "': Unable to create file");
                    }
                } catch (IOException e) {
                    writeLine("touch: cannot touch '" + fileName + "': " + e.getMessage());
                }
            }
        }
        
        private void sshCommand(String line) throws IOException {
            
            String[] sshArgs = line.split("\\s+");
            
            if(sshArgs.length < 2) {
                printFile("ssh.txt");
            }
            else {
                switch(sshArgs[1]){
                    
            case "-V":
                printFile("ssh_V.txt");
                break;
            case "-Q":
                if (sshArgs.length < 3) {
                    writeLine("option requires an argument -- Q");
                    printFile("ssh.txt");
                } else if ("cipher".equals(sshArgs[2])) {
                    printFile("ssh_Q_cipher.txt");
                    // ...
                } else if ("mac".equals(sshArgs[2])) {
                    printFile("ssh_Q_mac.txt");
                } else {
                    writeLine("ssh: Unsupported query for '-Q': " + sshArgs[2]);
                }
                break;
                default:
                printFile("ssh.txt");
                }
                
            }
            
        }
        
        private static long getFakeUptimeMillis() {
        // 14 days = 14 * 24 * 60 * 60 * 1000 ms
        return 14L * 24 * 60 * 60 * 1000;
        }
        
        private void printUptime() throws IOException {
            //Current time
            ZonedDateTime now = ZonedDateTime.now();
            String timeStr = now.format(DateTimeFormatter.ofPattern("HH:mm:ss"));

            long uptimeMillis = System.currentTimeMillis() - bootTimeMillis;
            long totalSeconds = uptimeMillis / 1000;
            long days = totalSeconds / (24 * 3600);
            long hours = (totalSeconds % (24 * 3600)) / 3600;
            long minutes = (totalSeconds % 3600) / 60;

            String uptimeStr = (days > 0)
                ? String.format(" up %d days, %2d:%02d,", days, hours, minutes)
                : String.format(" up %2d:%02d,", hours, minutes);

            // Generate number of users
            int users = 1 + (int)(Math.random() * 3); // 1 to 3 users

            // Generate load averages
            double load1 = Math.random() * 0.5;
            double load5 = Math.random() * 0.5;
            double load15 = Math.random() * 0.5;

            String result = String.format(" %s%s  %d user%s,  load average: %.2f, %.2f, %.2f",
                timeStr, uptimeStr, users, (users == 1 ? "" : "s"), load1, load5, load15);

            writeLine(result);
        }
        
        private void printDate() throws IOException {
            ZonedDateTime now = ZonedDateTime.now(TimeZone.getTimeZone("America/New_York").toZoneId());
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
            String formattedDate = now.format(formatter);
            writeLine(formattedDate);
        }
        
        private void simulatePing(String line) throws IOException {
            String[] parts = line.split("\\s+");
            if (parts.length < 2) {
                writeLine("ping: usage error: Destination address required");
                return;
            }

            String targetIP = parts[1];

            if ("10.23.45.67".equals(targetIP)) {
                // 'Succesful' ping to the address we allude to in 'history'.
                writeLine("PING " + targetIP + " (" + targetIP + ") 56(84) bytes of data.");

                for (int i = 1; i <= 4; i++) {
                    double time = 0.034 + Math.random() * 0.005;
                    writeLine(String.format("64 bytes from %s: icmp_seq=%d ttl=64 time=%.3f ms", targetIP, i, time));
                    try {
                        Thread.sleep(1000); //delay between ping replies
                    } catch (InterruptedException e) {
                        break;
                    }
                }

                writeLine("--- " + targetIP + " ping statistics ---");
                writeLine("4 packets transmitted, 4 received, 0% packet loss, time 4004ms");
                writeLine("rtt min/avg/max/mdev = 0.034/0.037/0.039/0.002 ms");
            } else {
                // Simulated unreachable ping
                writeLine("PING " + targetIP + " (" + targetIP + ") 56(84) bytes of data.");
                for (int i = 1; i <= 4; i++) {
                    writeLine(String.format("From %s icmp_seq=%d Destination Host Unreachable", "pbc-svr04", i));
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
                writeLine("--- " + targetIP + " ping statistics ---");
                writeLine("4 packets transmitted, 0 received, 100% packet loss, time 4004ms");
            }
        }
        /**
         * Simulates a wget download
         * Syntax: wget <URL> -O <filename>
         * Example: wget http://GenericUrl.com/malware -O trojan.sh
         */
        private void WgetCommand(String line) throws IOException {
            
            String[] parts = line.split("\\s+");

            String url = null;
            String outFileName = null;

            // usage: [ "wget", "<URL>", "-O", "<filename>" ]
            if (parts.length < 2) {
                writeLine("wget: missing URL");
                return;
            } else {
                url = parts[1];
                for (int i = 2; i < parts.length; i++) {
                    if ("-O".equals(parts[i]) && (i + 1 < parts.length)) {
                        outFileName = parts[i + 1];
                        break;
                    }
                }
            }

            // If no output file is specified:
            if (outFileName == null) {
                // Get a “basename” from the URL or default to "downloaded_file"
                outFileName = extractFilenameFromURL(url);
                if (outFileName.isEmpty()) {
                    outFileName = "downloaded_file";
                }
            }

            // store a new dummy file 
            // in the current directory of the fake filesystem.

            // get absolute path:
            String resolvedPath = currentDirectory.equals("/")
                ? "/" + outFileName
                : currentDirectory + "/" + outFileName;

            // find parent in FILESYSTEM
            int lastSlash = resolvedPath.lastIndexOf('/');
            String parentPath = (lastSlash <= 0) ? "/" : resolvedPath.substring(0, lastSlash);
            if (!FILESYSTEM.containsKey(parentPath)) {
                writeLine("wget: cannot write to " + parentPath + ": No such directory");
                return;
            }

            // insert into the parent's contents if not present
            List<String> parentContents = FILESYSTEM.get(parentPath);
            if (!parentContents.contains(outFileName)) {
                parentContents.add(outFileName);
            }

            // create the new file in honeyfiles
            File malwareFile = new File(HONEYFILES_DIR, outFileName);
            if (!malwareFile.exists()) {
                try (FileWriter fw = new FileWriter(malwareFile)) {
                    fw.write("Fake content from " + url + "\n");
                } catch (IOException e) {
                    writeLine("wget: error creating file '" + outFileName + "'");
                    logger.error("Error creating file: " + e.getMessage());
                    return;
                }
            }

            // local time for success message
            // place "start" and "end" time about 1 second apart.
            ZonedDateTime startTime = ZonedDateTime.now();
            ZonedDateTime endTime = startTime.plusSeconds(1);
            String dateFormat = "yyyy-MM-dd HH:mm:ss";
            String startString = startTime.format(java.time.format.DateTimeFormatter.ofPattern(dateFormat));
            String endString   = endTime.format(java.time.format.DateTimeFormatter.ofPattern(dateFormat));

            // wget output:
            writeLine("--" + startString + "--  " + url);
            writeLine("Resolving " + parseHostFromURL(url) + "... 198.51.100.42");
            writeLine("Connecting to " + parseHostFromURL(url) + "|198.51.100.42|:80... connected.");
            writeLine("HTTP request sent, awaiting response... 200 OK");
            writeLine("Length: ~2048 (application/octet-stream)");
            writeLine("Saving to: '" + outFileName + "'");
            writeLine(outFileName + "         100%[========>]    2.00K  --.-KB/s    in 0s");
            writeLine(endString + " (1.00 MB/s) - '" + outFileName + "' saved [2048/2048]");
        }

        /**
         * Extracts a simple filename from the URL string.
         * Example http://someurl.com/program.exe returns "program.exe".
         */
        private String extractFilenameFromURL(String url) {
            int slash = url.lastIndexOf('/');
            if (slash >= 0 && slash < url.length() - 1) {
                return url.substring(slash + 1);
            }
            // If there's no slash, or slash is last, return empty
            return "";
        }

        /**
         * Parse the host from a URL
         * example: http://exampleurl.com/file
         */
        private String parseHostFromURL(String url) {
            // Cut out "http://" and "https://", then up to next slash
            String stripped = url.replace("https://", "")
                                 .replace("http://", "");
            int slash = stripped.indexOf('/');
            if (slash >= 0) {
                return stripped.substring(0, slash);
            }
            return stripped;
        }

        // Go up one level (for cd ..)
        private String goUpOneLevel(String path) {
            if ("/".equals(path)) {
                return "/";
            }
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash <= 0) {
                return "/";
            }
            return path.substring(0, lastSlash);
        }

        // Print a text file from honeyfiles directory to the terminal
        private void printFile(String fileName) throws IOException {
            String filePath = HONEYFILES_DIR + "/" + fileName;
            try (FileReader fileReader = new FileReader(filePath);
                 BufferedReader br = new BufferedReader(fileReader)) {
                String lineOfTextFile;
                while ((lineOfTextFile = br.readLine()) != null) {
                    writeLine(lineOfTextFile);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // populate the fake directory by reading the contents of a text file
        private static void populateDirByFileRead(String dirFullPath, String fileName) {
            try {
                java.nio.file.Path binFilePath = java.nio.file.Paths.get(HONEYFILES_DIR, fileName);
                List<String> lines = java.nio.file.Files.readAllLines(binFilePath);
                FILESYSTEM.put(dirFullPath, new ArrayList<>(lines));
            } catch (IOException e) {
                e.printStackTrace();
                FILESYSTEM.put(dirFullPath, new ArrayList<>());
            }
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

        private String readLineWithEcho() throws IOException {
            StringBuilder sb = new StringBuilder();
            while (true) {
                int ch = in.read();
                if (ch == -1) {
                    // End of stream
                    return null;
                }

                if (ch == '\n' || ch == '\r') {
                    write("\r\n");
                    break;
                }
                else if (ch == 8 || ch == 127) {
                    // Backspace
                    if (sb.length() > 0) {
                        sb.deleteCharAt(sb.length() - 1);
                        // Move cursor back one, overwrite with space, move back again
                        write("\b \b");
                    }
                }
                else {
                    out.write(ch);
                    out.flush();
                    sb.append((char) ch);
                }
            }
            return sb.toString();
        }

        private void printBanner() throws IOException {
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

        private String getPrompt() {
            if ("/root".equals(currentDirectory)) {
                return "root@pbc-svr04:~# ";
            } else if (currentDirectory.startsWith("/root/")) {
                String subPath = currentDirectory.substring("/root".length());
                return "root@pbc-svr04:~" + subPath + "# ";
            } else {
                return "root@pbc-svr04:" + currentDirectory + "# ";
            }
        }

        private String getUname() {
            // Define system properties consistent with CentOS 8.
            String hostname = "pbc-svr04";
            String kernelVersion = "4.18.0-553.33.1.el8_10.x86_64";
            String arch = "x86_64 x86_64 x86_64 GNU/Linux";

            // Get current date in the expected format for uname command
            ZonedDateTime now = ZonedDateTime.now(TimeZone.getTimeZone("EST").toZoneId());
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss 'UTC' yyyy", Locale.ENGLISH);
            String formattedDate = now.format(formatter);

            // Construct uname -a output
            return String.format("Linux %s %s #1 SMP %s %s", hostname, kernelVersion, formattedDate, arch);
        }
    }
}

