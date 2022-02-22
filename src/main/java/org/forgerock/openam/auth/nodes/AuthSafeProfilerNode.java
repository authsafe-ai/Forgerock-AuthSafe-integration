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
import java.util.UUID;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;

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
       
        propertyId = config.propertyId();
        System.out.println(propertyId);
        sharedState.put("PROPERTY_ID", propertyId);
        
        
        String script = "var script = document.createElement('script');\n" +
                "script.type = 'text/javascript';\n" +
                "script.src = '%1$s'\n" +
                "document.getElementsByTagName('head')[0].appendChild(script);\n";

        
        String scriptsrc = String.format("https://p.authsafe.ai/as.js?p=%1$s*", propertyId);

        return send(Arrays.asList(new ScriptTextOutputCallback(String.format(script, scriptsrc)))).build();

    }

    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("PROPERTY_ID")};
    }
}