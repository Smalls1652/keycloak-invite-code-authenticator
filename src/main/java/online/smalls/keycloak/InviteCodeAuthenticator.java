package online.smalls.keycloak;

import java.text.MessageFormat;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * Authenticator for handling invite codes during user registration.
 */
public class InviteCodeAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(InviteCodeAuthenticator.class);

    public void validateInviteCode(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String inviteCode = context.getAuthenticatorConfig().getConfig().get("inviteCode");
        String suppliedInputCode = formData.getFirst("inviteCode");

        LOG.info(MessageFormat.format("Set code: {0} / Supplied code: {1}", inviteCode, suppliedInputCode));

        if (suppliedInputCode == null || !suppliedInputCode.equals(inviteCode)) {
            LOG.info("Invalid invite code was submitted.");

            Response failureResponse = context.form()
                    .setError("badCode")
                    .createForm("invite-code.ftl");

            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, failureResponse);
            return;
        }

        LOG.info("Invite code successfully validated.");
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realmModel, UserModel userModel) {
    }

    @Override
    public void close() {
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = context.form()
                .createForm("invite-code.ftl");

        context.challenge(challengeResponse);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        validateInviteCode(context);
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.isEmpty()) {
            forms.setFormData(formData);
        }

        return forms.createForm("invite-code.ftl");
    }
}
