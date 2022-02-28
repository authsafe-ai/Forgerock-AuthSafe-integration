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

import java.util.Arrays;
import java.util.Optional;

import javax.inject.Inject;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = AuthSafeProfilerNode.Config.class)
public class AuthSafeProfilerNode extends SingleOutcomeNode {

	private final Logger logger = LoggerFactory.getLogger(AuthSafeProfilerNode.class);
	private final Config config;

	
	public interface Config {

		@Attribute(order = 100)
		String propertyId();

	}

	
	@Inject
    public AuthSafeProfilerNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        JsonValue sharedState = context.sharedState;
        String propertyId;
        String requestString;
        
        propertyId = config.propertyId();
        System.out.println(propertyId);
        sharedState.put("PROPERTY_ID", propertyId);
         
        logger.error("We are in AuthSafeProfilerNode & propertyId is"+ propertyId);
        
        String script = "var script = document.createElement('script');\n" +
                "script.type = 'text/javascript';\n" +
                "script.src = '%1$s'\n" +                
                "document.getElementsByTagName('head')[0].appendChild(script);\n" +
                "var requestStringscript = document.createElement('script');\n" +
                "requestStringscript.innerHTML  = '%2$s'\n" +
                "document.getElementsByTagName('head')[0].appendChild(requestStringscript);\n";

        
        String scriptsrc = String.format("https://p.authsafe.ai/as.js?p=%1$s*", propertyId);
        
//        String requestStringscriptsrc = String.format("var device_id =_authsafe(\"getRequestString\");");
        
        String requestStringscriptsrc = String.format("var device_id = 500");
        
        
        if (context.getCallback(TextOutputCallback.class).isPresent() || context.getCallback(HiddenValueCallback.class)
                .isPresent()) {
        	requestString = context.getCallback(HiddenValueCallback.class).get().getValue();
        	logger.error("error-We are in AuthSafeProfilerNode If condition");
        	logger.error("error-We are in AuthSafeProfilerNode If condition context.toString()"+context.toString());
        	logger.error("error-We are in AuthSafeProfilerNode If condition context.getCallback(HiddenValueCallback.class).toString()"+context.getCallback(HiddenValueCallback.class).toString());
        	logger.error("error-We are in AuthSafeProfilerNode If condition context.getCallback(HiddenValueCallback.class).get().toString()"+context.getCallback(HiddenValueCallback.class).get().toString());
        	logger.error("error-We are in AuthSafeProfilerNode If condition context"+context);
        	logger.error("error-We are in AuthSafeProfilerNode If condition context.getCallback(HiddenValueCallback.class)"+context.getCallback(HiddenValueCallback.class));
        	logger.error("error-We are in AuthSafeProfilerNode If condition context.getCallback(HiddenValueCallback.class).get()"+context.getCallback(HiddenValueCallback.class).get());
        	logger.error("error-We are in AuthSafeProfilerNode If condition requestString"+requestString);
        	
        	sharedState.put("REQUEST_STRING", requestString);
//        	return goToNext().build();
        }
        
        logger.error("result******");  
        
        Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue).filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));
        if (result.isPresent()) {
            JsonValue newSharedState = context.sharedState.copy();
            logger.error("result"+result);            
            logger.error("newSharedState"+newSharedState);
            logger.error("newSharedState.toString()"+newSharedState.toString());
            logger.error("result.get()"+result.get());
            logger.error("result.get().toString()"+result.get().toString());
            newSharedState.put("REQUEST_STRING", result.get());
//            return goToNext().replaceSharedState(newSharedState).build();
        }
        return send(Arrays.asList(new ScriptTextOutputCallback(String.format(script, scriptsrc, requestStringscriptsrc))
        		,new HiddenValueCallback("AuthSafe Request String"))).replaceSharedState(sharedState).build();

    }

    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("PROPERTY_ID")};
    }
}