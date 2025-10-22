// Sample vulnerable Java code for testing PatchScout

import java.sql.*;
import javax.xml.parsers.*;
import java.io.*;

public class VulnerableCode {
    
    // SQL Injection
    public void getUserData(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(query);
    }
    
    // Command Injection
    public void executeCommand(String filename) throws IOException {
        Runtime.getRuntime().exec("cat " + filename);
    }
    
    // XXE Vulnerability
    public void parseXML(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    }
    
    // Hardcoded credentials
    private static final String DB_PASSWORD = "admin12345";
    private static final String API_KEY = "1234567890abcdef";
    
    // SSRF
    public void fetchURL(String userUrl) throws IOException {
        URL url = new URL(userUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.connect();
    }
}
