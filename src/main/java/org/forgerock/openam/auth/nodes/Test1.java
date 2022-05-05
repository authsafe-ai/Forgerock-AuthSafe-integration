package org.forgerock.openam.auth.nodes;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.util.Base64;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.json.JSONException;

import com.google.gson.Gson;

public class Test1 {
	public static void main(String[] args) throws IOException, InterruptedException, JSONException {

        // Recipient's email ID needs to be mentioned.
        String to = "ganeshsangle986@gmail.com";

        // Sender's email ID needs to be mentioned
        String from = "jignesh.shah.1988a@gmail.com";

        // Assuming you are sending email from through gmails smtp
        String host = "smtp.gmail.com";

        // Get system properties
        Properties properties = System.getProperties();

        // Setup mail server
        properties.put("mail.smtp.host", host);
        properties.put("mail.smtp.port", "465");
        properties.put("mail.smtp.ssl.enable", "true");
        properties.put("mail.smtp.auth", "true");

        // Get the Session object.// and pass username and password
        Session session = Session.getInstance(properties, new javax.mail.Authenticator() {

            protected PasswordAuthentication getPasswordAuthentication() {

                return new PasswordAuthentication("jignesh.shah.1988a@gmail.com", "ForgeRock@123");

            }

        });

        // Used to debug SMTP issues
        session.setDebug(true);

        try {
            // Create a default MimeMessage object.
            MimeMessage message = new MimeMessage(session);

            // Set From: header field of the header.
            message.setFrom(new InternetAddress(from));

            // Set To: header field of the header.
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));

            // Set Subject: header field
            message.setSubject("One Time Password (OTP) for user verification at XXX");

            // Now set the actual message
            message.setContent("<html><body>Dear User,<br>\r\n"
  					+ "<br>\r\n"
  					+ "We have detected some suspicious activities in your account on the below device:<br/>\r\n"
  					+ "<table border='1'>\r\n"
  					+ "  <tr>\r\n"
  					+ "    <th>Device</th>\r\n"
  					+ "    <th>Location</th>\r\n"
  					+ "    <th>Timestamp</th>\r\n"
  					+ "  </tr>\r\n"
  					+ "  <tr>\r\n"
  					+ "    <td>Alfreds Futterkiste</td>\r\n"
  					+ "    <td>Maria Anders</td>\r\n"
  					+ "    <td>Germany</td>\r\n"
  					+ "  </tr>\r\n"
  					+ "</table>"
  					+ "<br/>\r\n"
  					+ "So we have denied the user access to the account. You can reset your password from the same device to gain access to the account again.<br>\r\n"
  					+ "<br>\r\n"
  					+ "<a href=\"https://www.w3schools.com\">Click Here to reset your password.</a><br>\r\n"
  					+ "<br>\r\n"
  					+ "Regards,<br>\r\n"
  					+ "XXX team</body></html>", "text/html; charset=utf-8");
 			 
 			

            System.out.println("sending...");
            // Send message
            Transport.send(message);
            System.out.println("Sent message successfully....");
        } catch (MessagingException mex) {
            mex.printStackTrace();
        }

    }
	
//	String propertyID = "3115958146187663";
//    
//    String propertySecret = "oxHfSU0dHGkd1D6i";
//    
//    String plainCredentials = propertyID + ":" + propertySecret;
//    
//    String base64Credentials = new String(Base64.getEncoder().encode(plainCredentials.getBytes()));
//    
//    String authorizationHeader = "Basic " + base64Credentials;
//    
//    HttpClient client = HttpClient.newHttpClient();
//    
//    HttpRequest request = HttpRequest.newBuilder()
//            .uri(URI.create(String.format("https://a.authsafe.ai/v1/devices/%1$s/approve", "ganesh")))
//            .POST(BodyPublishers.ofString(""))
//            .header("Authorization", authorizationHeader)
//            .header("Content-Type", "application/json") 
//            .build();
//  
//    HttpResponse<String> response = client.send(request,
//            HttpResponse.BodyHandlers.ofString());
//  
//  ResponseBO obj = new Gson().fromJson(response.body(), ResponseBO.class);
//  System.out.println(obj.status);
//
//  System.out.println(response.toString());
//  System.out.println(request.headers());
//  System.out.println(request.method());
//  System.out.println(request.uri());
//  System.out.println(response.body());

	}
