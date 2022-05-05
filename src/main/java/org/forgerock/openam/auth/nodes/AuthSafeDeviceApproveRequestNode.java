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

import static org.forgerock.openam.auth.node.api.Action.send;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.inject.Inject;
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
import org.forgerock.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.gson.Gson;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

import groovyjarjarantlr.collections.List;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = AuthSafeDeviceApproveRequestNode.Config.class)
public class AuthSafeDeviceApproveRequestNode extends SingleOutcomeNode {

	private static final Logger logger = LoggerFactory.getLogger(AuthSafeDeviceApproveRequestNode.class);
	private final Config config;

	
	public interface Config {
		
	}
	
	@Inject
    public AuthSafeDeviceApproveRequestNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        JsonValue sharedState = context.sharedState;
        String OTP = sharedState.get("OTP").asString();
        logger.error("Device Management Request");
        logger.error("Device Management Request OTP:"+OTP);
        logger.error("SharedState"+ context.sharedState.toString());
        
        String propertyID = sharedState.get("PROPERTY_ID").asString();
        
        String propertySecret = sharedState.get("PROPERTY_SECRET").asString();

        String plainCredentials = propertyID + ":" + propertySecret;
        
        String base64Credentials = new String(Base64.getEncoder().encode(plainCredentials.getBytes()));
        
        String authorizationHeader = "Basic " + base64Credentials;
        
        HttpClient client = HttpClient.newHttpClient();
        
        HttpRequest request = HttpRequest.newBuilder()
        		.uri(URI.create(String.format("https://a.authsafe.ai/v1/devices/%1$s/approve", sharedState.get("responseDeviceId").asString()))).POST(BodyPublishers.ofString(""))
                .header("Authorization", authorizationHeader)
                .header("Content-Type", "application/json") 
                .build();
      
        HttpResponse<String> response = null;
		try {
			response = client.send(request,
			        HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
      
      ResponseBO obj = new Gson().fromJson(response.body(), ResponseBO.class);
      System.out.println(obj.status);

        logger.error(response.toString());
		logger.error(request.headers().toString());
		logger.error(request.method());
		logger.error(request.uri().toString());
		logger.error(response.body());
        
        return goToNext().build();
       
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState("CHALLENGE_OTP", true)};
    }

    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("DEVICE_API_REQ")};
    }
}