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
import org.forgerock.openam.identity.idm.IdentityUtils;
import javax.inject.Inject;
import static com.sun.identity.idm.IdType.USER;
import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
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
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = AuthSafeResetPasswordNode.Config.class)
public class AuthSafeResetPasswordNode extends SingleOutcomeNode {
	
	private final Logger logger = LoggerFactory.getLogger(AuthSafeResetPasswordNode.class);
	private final Config config;
	private final IdentityUtils identityUtils;

	
	public interface Config {


	}

	
	@Inject
    public AuthSafeResetPasswordNode(@Assisted Config config, IdentityUtils identityUtils) {
        this.config = config;
        this.identityUtils = identityUtils;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
    	JsonValue sharedState = context.sharedState;
    	final String realm = context.sharedState.get(REALM).asString();
    	    	
    	String userName = context.sharedState.get("username").asString();
    	String email = context.sharedState.get("objectAttributes").get("mail").asString();
    	

    	
    	String transientStateeoneTimePassword = context.transientState.get("oneTimePassword").asString();    	

    	
    	String ev;
    	
        if(StringUtils.isNotBlank(transientStateeoneTimePassword)) {
    		ev = "reset_password_failed";
    	}else {
    		ev = "reset_password_succeeded";
    	}
    	
        Optional<String> OuniversalId = identityUtils.getUniversalId(userName, realm, USER);
    	String[] uid = OuniversalId.get().split(",");


        String device_id = sharedState.get("device_id").asString();

        String ip = sharedState.get("ip").asString();
        String ua = sharedState.get("ua").asString();
        String ho = sharedState.get("ho").asString();
        String rf = sharedState.get("rf").asString();
        String url = sharedState.get("url").asString();
        String a = sharedState.get("a").asString();
        String ac = sharedState.get("ac").asString();
        String ae = sharedState.get("ae").asString();
        String al = sharedState.get("al").asString();
        
		  
		  
        String propertyID = sharedState.get("PROPERTY_ID").asString();

        String propertySecret = sharedState.get("PROPERTY_SECRET").asString();

	    String plainCredentials = propertyID + ":" + propertySecret;
	      
	      String base64Credentials = new String(Base64.getEncoder().encode(plainCredentials.getBytes()));
	      
	      String authorizationHeader = "Basic " + base64Credentials;
	      	
	      JSONObject object = new JSONObject();
	      String json = null;
	      try {
			object.put("ev", ev);
			object.put("dID", device_id);
		      
		      JSONObject uex = new JSONObject();
		      uex.put("email", "");
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


		} catch (JSONException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	      	      
	      HttpClient client = HttpClient.newHttpClient();
	     
	      HttpRequest request = HttpRequest.newBuilder()
	                .uri(URI.create("https://a.authsafe.ai/v1/reset-password"))
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

		return goToNext().build();
    }
    

    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState("RESET_REQEUST", true)};
    }
    
    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("PASSWORD_RESETs")};
    }
}