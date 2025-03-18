package online.smalls.keycloak;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * Factory for <code>InviteCodeAuthenticator</code>
 *
 * @see InviteCodeAuthenticator
 */
public class InviteCodeAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "invite-code";

    private static final InviteCodeAuthenticator SINGLETON = new InviteCodeAuthenticator();

    private static final Logger LOG = Logger.getLogger(InviteCodeAuthenticatorFactory.class);

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory sessionFactory) {
        LOG.info("Invite code provider initialized.");
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Invite code";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Require an invite code during user account registration.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("inviteCode")
                .label("Invite code")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("The invite code users will need during registration.")
                .defaultValue("your-invite-code")
                .add()
                .build();
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.isEmpty()) {
            forms.setFormData(formData);
        }

        return forms.createForm("invite-code.ftl");
    }
}
