package mohandesi.it.demo.oauth.config.security.client;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Configuration
public class ClientsConfig {
  @Bean
  public RegisteredClientRepository registeredClientRepository() {

    return new InMemoryRegisteredClientRepository(createDummyRegisteredClients());
  }

  private static RegisteredClient[] createDummyRegisteredClients() {

    RegisteredClient publicClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("public")
            .clientSecret("public")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .redirectUri("http://localhost:8080/oauth2/code/authzcode.xhtml")
            .scope(OidcScopes.OPENID)
            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
            .build();
    RegisteredClient resourceServer9000 =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("resource9000")
            .clientSecret("resource9000")
            .clientName("resource9000")
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
            .build();
    RegisteredClient resourceServer9005 =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("resource9005")
            .clientSecret("resource9005")
            .clientName("resource9005")
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
            .build();

    return new RegisteredClient[] {publicClient, resourceServer9000, resourceServer9005};
  }
}
