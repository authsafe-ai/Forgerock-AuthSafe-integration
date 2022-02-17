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

package com.securelayer7.AuthNode;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = RequestStringNode.Config.class)
public class RequestStringNode extends SingleOutcomeNode {

	private final Logger logger = LoggerFactory.getLogger(RequestStringNode.class);
	private final Config config;

	
	public interface Config {

		@Attribute(order = 100)
		String propertyId();

	}

	
	@Inject
	public RequestStringNode(@Assisted Config config) {
		this.config = config;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		JsonValue sharedState = context.sharedState;

		String propertyId = context.request.headers.get(config.propertyId()).get(0);

		String script = String.format("<html> <head> <script src=\"https://p.authsafe.ai/as.js?p=%1$s*\"></script> %1$s <script>\r\n"
				+ "_authsafe(\"userInit\", 1);**"
				+ "</script> </html> </head>", propertyId);
        
		

		return send(Arrays.asList(new ScriptTextOutputCallback(script))).replaceSharedState(sharedState).build();

	}
}
