package authsafe.ai;

import static org.forgerock.openam.auth.node.api.Action.send;
import static authsafe.ai.AuthSafeHelper.PROPERTY_ID;
import static authsafe.ai.AuthSafeHelper.PROPERTY_SECRET;

import java.util.Arrays;
import java.util.UUID;

import javax.inject.Inject;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = AuthSafePixelNode.Config.class)
public class AuthSafePixelNode extends SingleOutcomeNode {
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * The AuthSafe Property Id
         */
        @Attribute(order = 100)
        String propertyId();
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     * @param config The service config.
     */
    @Inject
    public AuthSafePixelNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        JsonValue sharedState = context.sharedState;

        String scriptSrc = String.format("https://p.authsafe.ai/as.js?p=%1$s", config.propertyId());
        String script = "var script = document.createElement('script');\n" +
                "script.type = 'text/javascript';\n" +
                "script.src = '%1$s'\n" +
                "document.getElementsByTagName('head')[0].appendChild(script);\n";


        return send(Arrays.asList(new ScriptTextOutputCallback(String.format(script, scriptSrc))).replaceSharedState(sharedState).build();
    }

    @Override
    public OutputState[] getOutputs() {
            return new OutputState[] {new OutputState("")};
    }
}

