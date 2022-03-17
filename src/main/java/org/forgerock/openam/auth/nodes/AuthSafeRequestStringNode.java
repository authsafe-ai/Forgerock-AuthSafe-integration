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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.google.gson.Gson;


/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = AuthSafeRequestStringNode.AuthSafeOutcomeProvider.class, configClass = AuthSafeRequestStringNode.Config.class)
public class AuthSafeRequestStringNode implements Node {
	
	private final Logger logger = LoggerFactory.getLogger(AuthSafeRequestStringNode.class);
	private final Config config;

	
	public interface Config {


	}

	
	@Inject
    public AuthSafeRequestStringNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
    	JsonValue sharedState = context.sharedState;
    	    	
    	String userName = context.sharedState.get("username").asString();
    	String emailAddress = context.sharedState.get("emailAddress").asString();
    	String universalId = context.sharedState.get("universalId").asString();
    	
    	logger.error("username"+ userName);
    	logger.error("emailAddress"+ emailAddress);
    	logger.error("universalId"+ universalId);
    	
    	String transientStateemailAddress = context.transientState.get("emailAddress").asString();
    	String transientStateuniversalId = context.transientState.get("universalId").asString();
    	
    	logger.error("transientStateemailAddress"+ transientStateemailAddress);
    	logger.error("transientStateuniversalId"+ transientStateuniversalId);
    	
    	String secureStateemailAddress = context.getSecureState("emailAddress").asString();
    	String secureStateuniversalId = context.getSecureState("universalId").asString();
    	
    	logger.error("secureStateemailAddress"+ secureStateemailAddress);
    	logger.error("secureStateuniversalId"+ secureStateuniversalId);
    	
    	String identityResource = context.identityResource;
    	logger.error("identityResource"+ identityResource);
    	
    	Optional<String> OuniversalId = context.universalId;
    	String[] uid = OuniversalId.get().split(",");
    	
    	logger.error("OuniversalId"+ OuniversalId.get());
    	logger.error("uid"+ uid[0].replace("id=", ""));
    	
    	
    	logger.error("SharedState"+ context.sharedState.toString());
    	logger.error("transientState"+ context.transientState.toString());
    	
        String device_id = sharedState.get("device_id").asString();
        logger.error("Device ID: " + device_id);

        String ip = sharedState.get("ip").asString();
        String ua = sharedState.get("ua").asString();
        String ho = sharedState.get("ho").asString();
        String rf = sharedState.get("rf").asString();
        String url = sharedState.get("url").asString();
        String a = sharedState.get("a").asString();
        String ac = sharedState.get("ac").asString();
        String ae = sharedState.get("ae").asString();
        String al = sharedState.get("al").asString();
        
		  
		  
	      String propertyID = "3115958146187663";
	      
	      String propertySecret = "oxHfSU0dHGkd1D6i";
	      
	      String plainCredentials = propertyID + ":" + propertySecret;
	      
	      String base64Credentials = new String(Base64.getEncoder().encode(plainCredentials.getBytes()));
	      
	      String authorizationHeader = "Basic " + base64Credentials;
	      	
	      JSONObject object = new JSONObject();
	      String json = null;
	      try {
			object.put("ev", "login_succeeded");
			object.put("dID", device_id);
		      
		      JSONObject uex = new JSONObject();
		      uex.put("email", "Ganeshsangle986@gmail.com");
		      uex.put("username", userName);
		      
		      object.put("uex", uex);
		      
		      JSONObject h = new JSONObject();
		      h.put("ip", ip);
		      h.put("ua", ua);
		      h.put("ho", ho);
		      h.put("rf", rf);
		      
		      JSONObject acObj = new JSONObject();
		      acObj.put("a", a);
		      acObj.put("ac", ac);
		      acObj.put("ae", ae);
		      acObj.put("al", al);
		      
		      h.put("ac", acObj);
		      h.put("url", url);
		      
		      object.put("h", h);
		      object.put("uID", uid[0].replace("id=", ""));
		      
		      json = object.toString();
		      
		      logger.error("json request:"+json);

		} catch (JSONException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	      	      
	      HttpClient client = HttpClient.newHttpClient();
	     
	      HttpRequest request = HttpRequest.newBuilder()
	                .uri(URI.create("https://a.authsafe.ai/v1/login"))
	                .POST(BodyPublishers.ofString(json))
	                .header("Authorization", authorizationHeader)
	                .header("Content-Type", "application/json")
	                .build();
	      
	      HttpResponse<String> response = null;
	      ResponseBO obj = null;
		try {
			response = client.send(request,
			            HttpResponse.BodyHandlers.ofString());
			obj = new Gson().fromJson(response.body(), ResponseBO.class);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		logger.error(response.toString());
		logger.error(request.headers().toString());
		logger.error(request.method());
		logger.error(request.uri().toString());
		logger.error(response.body());

		

		String responseStatus = obj.status;
        if (StringUtils.isEmpty(responseStatus)) {
            throw new NodeProcessException("Error, Not received response");
        }
        if (StringUtils.equals(AuthSafeResultOutcome.ALLOW.toString(), responseStatus)) {
        	logger.error("ALLOW");
            return Action.goTo(AuthSafeResultOutcome.ALLOW.name()).build();
        } else if (StringUtils.equals(AuthSafeResultOutcome.CHALLENGE.toString(), responseStatus)) {
        	logger.error("CHALLENGE");
            return Action.goTo(AuthSafeResultOutcome.CHALLENGE.name()).build();
        } else if (StringUtils.equals(AuthSafeResultOutcome.DENY.toString(), responseStatus)) {
        	logger.error("DENY");
            return Action.goTo(AuthSafeResultOutcome.DENY.name()).build();
        }
        return Action.goTo(AuthSafeResultOutcome.DENY.name()).build();

    }
    
    private enum AuthSafeResultOutcome {

        ALLOW("allow"),
        CHALLENGE("challenge"),
        DENY("deny");

        private final String stringName;

        AuthSafeResultOutcome(String stringName) {
            this.stringName = stringName;
        }

        @Override
        public String toString() {
            return stringName;
        }
    }

    public static class AuthSafeOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
           
            return ImmutableList.of(
                    new Outcome(AuthSafeResultOutcome.ALLOW.name(), "Allow"),
                    new Outcome(AuthSafeResultOutcome.CHALLENGE.name(), "Challenge"),
                    new Outcome(AuthSafeResultOutcome.DENY.name(), "Deny"));
        }
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState("PROPERTY_ID", true)};
    }
    
    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("REQUEST_STRING")};
    }
}