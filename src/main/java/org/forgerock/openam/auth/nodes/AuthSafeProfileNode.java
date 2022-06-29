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
import java.util.ArrayList;
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
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import org.forgerock.openam.sm.annotations.adapters.Password;
import groovyjarjarantlr.collections.List;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = AuthSafeProfileNode.Config.class)
public class AuthSafeProfileNode extends SingleOutcomeNode {

	private static final Logger logger = LoggerFactory.getLogger(AuthSafeProfileNode.class);
	private final Config config;

	
	public interface Config {

		@Attribute(order = 100)
		String propertyId();
		
		@Attribute(order = 200)
		@Password
		char[] propertySecret();

	}
	
	@Inject
    public AuthSafeProfileNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        JsonValue sharedState = context.sharedState;
        ExternalRequestContext request = context.request;
        
        String propertyId;
        String propertySecret;
        
        propertyId = config.propertyId();
        propertySecret = String.valueOf(config.propertySecret());

        sharedState.put("PROPERTY_ID", propertyId);
        sharedState.put("PROPERTY_SECRET", propertySecret);
        
        String ip = request.clientIp;
        String ua = request.headers.get("user-agent").get(0); 
        String ho = request.headers.get("host").get(0);
        String rf = request.headers.get("referer").get(0);
        String url = request.serverUrl;
        String a = request.headers.get("accept").get(0);
//        String ac = request.headers.get("accept").toString();//TODO:Not found in headers
        String ae = request.headers.get("accept-encoding").get(0);
        String al = request.headers.get("accept-language").get(0);

        
        
        
        sharedState.put("ip", ip);
        sharedState.put("ua", ua);
        sharedState.put("ho", ho);
        sharedState.put("rf", rf);
        sharedState.put("url", url);
        
        sharedState.put("a", a);
        sharedState.put("ac", "");
        sharedState.put("ae", ae);
        sharedState.put("al", al);
        

        String aScript = getScript(propertyId);

        Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue).
                filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));
        if (result.isPresent()) {
            String resultValue = result.get();
            JsonValue newSharedState = context.sharedState.copy();
            newSharedState.put("device_id", resultValue);
            return goToNext().replaceSharedState(newSharedState).build();
        } else {
            ImmutableList<Callback> callbacks = getScriptAndSelfSubmitCallback(aScript);
            return send(callbacks).build();
        }
    }

    public static ImmutableList<Callback> getScriptAndSelfSubmitCallback(String aNodeScript) {
        String clientSideScriptExecutorFunction = createClientSideScriptExecutorFunction(aNodeScript);

        ScriptTextOutputCallback scriptAndSelfSubmitCallback = new ScriptTextOutputCallback(
                clientSideScriptExecutorFunction);

        HiddenValueCallback hiddenValueCallback = new HiddenValueCallback("AuthSafeRequestString", "false");
        return ImmutableList.of(scriptAndSelfSubmitCallback, hiddenValueCallback);

    }

    public static String getScript(String propertyId) {
        String script = "var script = document.createElement('script');\n" +
                "script.type = 'text/javascript';\n" +
                "script.src = '%1$s'\n" +
                "document.getElementsByTagName('head')[0].appendChild(script);\n" +
                "var requestStringscript = document.createElement('script');\n" +
//                "requestStringscript.innerHTML  = '%2$s'\n" +
                "var device_id;\n" +
                "document.getElementsByTagName('body')[0].appendChild(requestStringscript);\n" +
                "var submitCollectedData = function functionSubmitCollectedData() {\n" +
                "    if (typeof loginHelpers !== 'undefined') {\n" +
                "        loginHelpers.setHiddenCallback('AuthSafeRequestString', device_id);\n" +
                "    } else {\n" +
                "    }\n" +
                "}\n" +
                "\n" +
                "if (typeof loginHelpers !== 'undefined') {\n" +
                "    if (loginHelpers) {\n" +
                "        loginHelpers.nextStepCallback(submitCollectedData)\n" +
                "    }\n" +
                "} else {\n" +
                "    var userNameEventListener = function functionUserNameEventListener() {\n" +
                "        var userNameField = document.getElementsByClassName(\"form-control\")[0];\n" +
                "        userNameField.removeEventListener(\"blur\", userNameEventListener);\n" +
                "        var submitButton = document.getElementsByClassName(\"btn-primary\")[0];\n" +
                "        submitButton.addEventListener(\"click\", submitCollectedData, false);\n" +
                "    };\n" +
                "\n" +
                "    var submitCollectedData = function functionSubmitCollectedData() {\n" +
                "        var outputVariable = document.forms[0].elements['AuthSafeRequestString'];\n" +
                "        outputVariable.value = _authsafe(\"getRequestString\");\n" +
                "    }\n" +
                "\n" +
                "    if (document.getElementsByClassName(\"form-control\")[0] != undefined) {\n" +
                "        var userNameField = document.getElementsByClassName(\"form-control\")[0];\n" +
                "        userNameField.addEventListener(\"blur\", userNameEventListener);\n" +
                "    }\n" +
                "}";


        String scriptsrc = String.format("https://p.authsafe.ai/as.js?p=%1$s", propertyId);


        return String.format(script, scriptsrc);

    }

    private static String createClientSideScriptExecutorFunction(String script) {
        return String.format(
                "(function(output) {\n" +
                        "    %s\n" + // script
                        "}) (document);\n",
                script
        );
    }

    public static String readFileString(String path) {
        try {
            InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
            String data = readAllLines(in);
            in.close();
            return data;
        } catch (NullPointerException | IOException e) {
            logger.error("Can't read file " + path, e);
            return null;
        }
    }

    public static String readAllLines(InputStream in) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        return reader.lines().parallel().collect(Collectors.joining("\n"));
    }

    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("PROPERTY_ID")};
    }
}