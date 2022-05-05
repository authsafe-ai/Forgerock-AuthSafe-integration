/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;



import static com.google.common.base.Preconditions.checkArgument;
import static org.forgerock.openam.auth.node.api.Action.suspend;
import static org.forgerock.openam.auth.node.api.SuspendedTextOutputCallback.info;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Properties;

import javax.inject.Inject;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.SuspendedTextOutputCallback;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
//import org.forgerock.openam.auth.nodes.OTPGenerator;
/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = AuthSafeEmailSuspendNode.Config.class)
public class AuthSafeEmailSuspendNode extends SingleOutcomeNode {

	private static final Logger logger = LoggerFactory.getLogger(AuthSafeEmailSuspendNode.class);
	private final Config config;

	
	public interface Config {
		
	}
	
	@Inject
    public AuthSafeEmailSuspendNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
	public Action process(TreeContext context) {
    	logger.error("EmailSuspendNode started");
        if (context.hasResumedFromSuspend()) {
            return goToNext().build();
        }
        
        return suspend(resumeURI -> createSuspendOutcome(context, resumeURI)).build();

	}
    
    private SuspendedTextOutputCallback createSuspendOutcome(TreeContext context, URI resumeURI) {

        String infomessage = "An email has been sent to the address you entered. Click the link in that email to proceed.";

        logger.error("Sending email");
     // Recipient's email ID needs to be mentioned.
     	String to = context.sharedState.get("EMAIL_ADDRESS").asString();

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

     			String[] referer = context.sharedState.get("rf").asString().split("/"); 
    			String website = referer[2].substring(0, referer[2].indexOf(":"));
    			
     			// Set Subject: header field
     			message.setSubject("Suspicious login detected at "+website);

//     			Parser uaParser = new Parser();
//     			Client c = uaParser.parse(context.sharedState.get("ua").asString());
//     			String browser = c.userAgent.family;
//     			String operatingSystem = c.os.family+c.os.major;
     			
     			DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss");
     			LocalDateTime now = LocalDateTime.now();
     			String dayofMonthSuffix = getDayOfMonthSuffix(now.getDayOfMonth());
     			String Timestamp = dtf.format(now).substring(0, 2)+dayofMonthSuffix+dtf.format(now).substring(2, dtf.format(now).length());
     					
     			message.setContent("<html><body>Dear User,<br>\r\n"
      					+ "<br>\r\n"
      					+ "We have detected some suspicious activities in your account on the below device:<br>\r\n"
      					+ "<table border='1' cellspacing='0'cellpadding='0'>\r\n"
      					+ "  <tr>\r\n"
      					+ "    <th>Device</th>\r\n"
      					+ "    <th>Location</th>\r\n"
      					+ "    <th>Timestamp</th>\r\n"
      					+ "  </tr>\r\n"
      					+ "  <tr>\r\n"
      					+ "    <td>"+context.sharedState.get("name").asString()+"</td>\r\n"
      					+ "    <td>"+context.sharedState.get("location").asString()+"</td>\r\n"
      					+ "    <td>"+Timestamp+"</td>\r\n"
      					+ "  </tr>\r\n"
      					+ "</table>"
      					+ "<br>\r\n"
      					+ "So we have denied the user access to the account. You can reset your password from the same device to gain access to the account again.<br>\r\n"
      					+ "<br>\r\n"
      					+ "<a href="+resumeURI+">Click Here to reset your password.</a><br>\r\n"
      					+ "<br>\r\n"
      					+ "Regards,<br>\r\n"
      					+ website+" team</body></html>", "text/html");
     			 
     			System.out.println("sending...");
     			// Send message
     			Transport.send(message);
     			System.out.println("Sent message successfully....");
     		} catch (MessagingException mex) {
     			mex.printStackTrace();
     		}
        return info(infomessage);
    }


    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState("REQUEST_STRING", true)};
    }
    
    String getDayOfMonthSuffix(final int n) {
        checkArgument(n >= 1 && n <= 31, "illegal day of month: " + n);
        if (n >= 11 && n <= 13) {
            return "th";
        }
        switch (n % 10) {
            case 1:  return "st";
            case 2:  return "nd";
            case 3:  return "rd";
            default: return "th";
        }
    }

    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("CHALLENGE_OTP")};
    }
}