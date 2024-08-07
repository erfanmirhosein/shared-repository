package mohandesi.it.demo.oauth.config.security.oauth2;

import java.util.HashSet;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class OAuth2SecurityConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {

    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(oidCustomizer -> oidCustomizer.userInfoEndpoint(userInfoEndpoint -> {}))
        .tokenIntrospectionEndpoint(
            tokenIntrospectionEndpoint ->
                tokenIntrospectionEndpoint.authenticationProvider(
                    new CheckAuthoritiesOAuth2TokenIntrospectionAuthenticationProvider(
                        getRegisteredClientRepository(http), getAuthorizationService(http))));

    http.exceptionHandling(
        exceptionHandlingCustomizer ->
            exceptionHandlingCustomizer.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")));

    return http.build();
  }

  @Bean
  public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueTokenCustomizer() {
    return context -> {
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

        Set<GrantedAuthority> principalGrantedAuthorities =
            new HashSet<>(context.getPrincipal().getAuthorities());

        context
            .getClaims()
            .claims(claims -> claims.put("granted-authorities", principalGrantedAuthorities));
      }
    };
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }
}
