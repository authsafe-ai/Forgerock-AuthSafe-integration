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
import static org.forgerock.openam.auth.nodes.helpers.AuthNodeUserIdentityHelper.getAMIdentity;
import javax.inject.Inject;
import org.forgerock.openam.utils.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
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
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.identity.idm.IdentityUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.google.gson.Gson;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.iplanet.sso.SSOException;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.Optional;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = AuthSafeRiskActionNode.AuthSafeOutcomeProvider.class, configClass = AuthSafeRiskActionNode.Config.class)
public class AuthSafeRiskActionNode implements Node {
	
	private final Logger logger = LoggerFactory.getLogger(AuthSafeRiskActionNode.class);
	private final Config config;
    private final CoreWrapper coreWrapper;
    private final IdentityUtils identityUtils;
	
	public interface Config {

		@Attribute(order = 300)
        default Boolean TakeAction() {
            return false;
        }

	}

	
	@Inject
    public AuthSafeRiskActionNode(@Assisted Config config, CoreWrapper coreWrapper,
            IdentityUtils identityUtils) {
        this.config = config;
        this.coreWrapper = coreWrapper;
        this.identityUtils = identityUtils;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
		
        if (config.TakeAction()) {
        	logger.error("TRUE");
            return Action.goTo(AuthSafeResultOutcome.TRUE.name()).build();
        } else {
        	logger.error("FALSE");
            return Action.goTo(AuthSafeResultOutcome.FALSE.name()).build();
        } 
        
    }
    
    private enum AuthSafeResultOutcome {

        TRUE("true"),
        FALSE("false");

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
                    new Outcome(AuthSafeResultOutcome.TRUE.name(), "True"),
                    new Outcome(AuthSafeResultOutcome.FALSE.name(), "False"));
        }
    }
    

    
    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState("", true)};
    }
    
    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("")};
    }
}