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

import java.util.Properties;

import javax.inject.Inject;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.security.auth.callback.Callback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.Strings;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

import groovyjarjarantlr.collections.List;
/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = AuthSafeOTPSenderNode.Config.class)
public class AuthSafeOTPSenderNode extends SingleOutcomeNode {

	private static final Logger logger = LoggerFactory.getLogger(AuthSafeOTPSenderNode.class);
	private final Config config;

	
	public interface Config {

        @Attribute(order = 100)
        String smtp_email();

        @Attribute(order = 200)
        @Password
        char[] smtp_password();

        @Attribute(order = 300)
        String smtp_auth();

        @Attribute(order = 400)
        String smtp_ssl_enable();

        @Attribute(order = 500)
        String smtp_host();
        
        @Attribute(order = 600)
        String smtp_port();
		
	}
	
	@Inject
    public AuthSafeOTPSenderNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
	public Action process(TreeContext context) {
		JsonValue sharedState = context.sharedState;

		logger.error("OTPSender");
		int length = 5;

		logger.error("transientState" + context.transientState.toString());

		// Recipient's email ID needs to be mentioned.
		String to = sharedState.get("EMAIL_ADDRESS").asString();

		// Sender's email ID needs to be mentioned
		String from = config.smtp_email();

		// Assuming you are sending email from through gmails smtp
		String host = config.smtp_host();

		// Get system properties
		Properties properties = System.getProperties();

		// Setup mail server
		properties.put("mail.smtp.host", host);
		properties.put("mail.smtp.port", config.smtp_port());
		properties.put("mail.smtp.ssl.enable", config.smtp_ssl_enable());
		properties.put("mail.smtp.auth", config.smtp_auth());

		// Get the Session object.// and pass username and password
		Session session = Session.getInstance(properties, new javax.mail.Authenticator() {

			protected PasswordAuthentication getPasswordAuthentication() {

				return new PasswordAuthentication(config.smtp_email(), String.valueOf(config.smtp_password()));

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

			String[] referer = sharedState.get("rf").asString().split("/"); 
			String website = referer[2].substring(0, referer[2].indexOf(":"));
			
			// Set Subject: header field
			message.setSubject("One Time Password (OTP) for user verification at "+website);

			String transientStateeoneTimePassword = context.transientState.get("oneTimePassword").asString();    	
	    				
			
			// Now set the actual message
			message.setText("Dear User,\r\n"
					+ "\r\n"
					+ "The One Time Password (OTP) for your user verification at "+website+" is "+transientStateeoneTimePassword+".\r\n"
					+ "\r\n"
					+ "This OTP is valid for 5 minutes or 1 successful attempt, whichever is earlier. Please note that this OTP is valid only for this user verification process and cannot be used for any other transaction.\r\n"
					+ "\r\n"
					+ "Please do not share this One Time Password with anyone.\r\n"
					+ "\r\n"
					+ "Regards,\r\n"
					+ website+" team");

			System.out.println("sending...");
			// Send message
			Transport.send(message);
			System.out.println("Sent message successfully....");
		} catch (MessagingException mex) {
			mex.printStackTrace();
		}
		return goToNext().build();

	}

    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState("REQUEST_STRING", true)};
    }

    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("CHALLENGE_OTP")};
    }
}