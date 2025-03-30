package com.FIU.sshhoneypot;

import static spark.Spark.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONArray;
import org.json.JSONObject;
//imports for AI API call:
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Java Spark web server for the web dashboard of the SSH honeypot
 */
public class WebDashboard {

    public static void startServer() {
        
        //bind the web server to the localhost interface so that no other machine can access the Spark server.
        ipAddress("127.0.0.1");
        // Start Spark on port 4567
        port(4567);

        // Serve static files from src/main/resources/public
        staticFiles.location("/public");

        // Route that returns the entire log file as plain text:
        get("/log", (req, res) -> {
            res.type("text/plain");
            return getLogFileContent("honeypot.log");
        });

        // Route for summary of the log
        get("/summary", (req, res) -> {
              res.type("application/json");
               String rawLog = getLogFileContent("honeypot.log");
               int lineCount = rawLog.split("\n").length;
               String fallbackSummary = "Total log lines: " + lineCount;

              // Truncate the log if it's too big
              String[] lines = rawLog.split("\n");
              int maxLines = 50; // You can make this smaller if needed
              StringBuilder truncated = new StringBuilder();
              for (int i = Math.max(0, lines.length - maxLines); i < lines.length; i++) {
                  truncated.append(lines[i]).append("\n");
    }
    String truncatedLog = truncated.toString();

    // Try calling OpenAI if we have an API key
    String apiKey = System.getenv("API_KEY"); // your key
    String projectId = System.getenv("PROJ_ID"); // your project ID
    if (apiKey == null || apiKey.isEmpty()) {
        return "{\"summary\": \"" + escapeJson(fallbackSummary) + "\"}";
    } else {
        String aiSummary = summarizeWithOpenAI(truncatedLog, apiKey, projectId); 

        if (aiSummary.startsWith("Error:")) {
            return "{\"summary\": \"" + escapeJson(fallbackSummary)
                    + "\", \"error\": \"" + escapeJson(aiSummary) + "\"}";
        }

        return "{\"summary\": \"" + escapeJson(aiSummary) + "\"}";
    }
});

    }

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
private static String summarizeWithOpenAI(String logContent, String apiKey, String projectId) {
    String endpoint = "https://api.openai.com/v1/chat/completions";

    // Build JSON request safely
    JSONObject systemMsg = new JSONObject()
            .put("role", "system")
            .put("content", "This is the log from an SSH honeypot. As a security assistant, explain the log of what the intruder was trying to do concisely. Keep it around 200 words.");

    JSONObject userMsg = new JSONObject()
            .put("role", "user")
            .put("content", logContent);

    JSONArray messages = new JSONArray()
            .put(systemMsg)
            .put(userMsg);

    JSONObject requestBodyJson = new JSONObject()
            .put("model", "gpt-4o")
            .put("messages", messages)
            .put("temperature", 0.3)
            .put("max_tokens", 600);

    String requestBody = requestBodyJson.toString(); // valid JSON

    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + apiKey)
            .header("OpenAI-Project", projectId)
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

    HttpClient client = HttpClient.newHttpClient();
    try {
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Debug output
        System.out.println("---- GPT API Response ----");
        System.out.println("Status Code: " + response.statusCode());
        System.out.println("Raw JSON:");
        System.out.println(response.body());
        System.out.println("--------------------------");

        if (response.statusCode() != 200) {
            return "Error: " + response.body();
        }

        JSONObject responseJson = new JSONObject(response.body());
        JSONArray choices = responseJson.getJSONArray("choices");
        JSONObject message = choices.getJSONObject(0).getJSONObject("message");
        return message.getString("content").trim();

    } catch (Exception e) {
        e.printStackTrace();
        return "Error: " + e.getMessage();
    }
}
    private static String escapeJson(String text) {
        return text.replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r");
    }
}

