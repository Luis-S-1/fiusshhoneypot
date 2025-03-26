package com.FIU.sshhoneypot;

import static spark.Spark.*;

import spark.Response;
import spark.Request;
import spark.Route;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files; 
import java.nio.file.Paths;

/**
 * Java Spark web server for the web dashboard of the SSH honeypot
 */
public class WebDashboard {

    public static void startServer() {
        
        //bind the web server to the localhost interface so that no other machine can access the Spark server.
        ipAddress("127.0.0.1");
        // Start Spark on port 4567
        port(4567);

        // Serve static files from src/main/resources/public by default
        // We can also place the static files anywhere and call:
        // staticFiles.location("/public");
        staticFiles.location("/public"); 

        // Route that returns the entire log file as plain text:
        get("/log", (req, res) -> {
            res.type("text/plain");
            return getLogFileContent("honeypot.log");
        });

        // Route to do some minimal "summary" of the log:
        // Later we could incorporate API calls to an AI (for the AI summary of log events)
        get("/summary", (req, res) -> {
            res.type("application/json");
            String rawLog = getLogFileContent("honeypot.log");
            // For now we're just returning the number of lines in the log as a "summary"
            int lineCount = rawLog.split("\n").length;
            return "{\"summary\": \"Total log lines: " + lineCount + "\"}";
        });
    }

    // Method to read the log file:
    private static String getLogFileContent(String fileName) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append(System.lineSeparator());
            }
        } catch (IOException e) {
            return "Error reading " + fileName + ": " + e.getMessage();
        }
        return sb.toString();
    }
}
