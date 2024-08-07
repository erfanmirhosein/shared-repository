package mohandesi.it.demo.oauth.config.security.oauth2;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import mohandesi.it.demo.oauth.config.security.oauth2.provider.OAuth2AuthorityIntrospectionProvider;

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
                    new OAuth2AuthorityIntrospectionProvider(
                        OAuth2ConfigurerUtils.getRegisteredClientRepository(http),
                        OAuth2ConfigurerUtils.getAuthorizationService(http))));

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

  private abstract static class OAuth2ConfigurerUtils {
    static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
      OAuth2AuthorizationService authorizationService =
          httpSecurity.getSharedObject(OAuth2AuthorizationService.class);
      if (authorizationService == null) {
        authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);
        if (authorizationService == null) {
          authorizationService = new InMemoryOAuth2AuthorizationService();
        }
        httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
      }
      return authorizationService;
    }

    static RegisteredClientRepository getRegisteredClientRepository(HttpSecurity httpSecurity) {
      RegisteredClientRepository registeredClientRepository =
          httpSecurity.getSharedObject(RegisteredClientRepository.class);
      if (registeredClientRepository == null) {
        registeredClientRepository = getBean(httpSecurity, RegisteredClientRepository.class);
        httpSecurity.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
      }
      return registeredClientRepository;
    }

    static <T> T getBean(HttpSecurity httpSecurity, Class<T> type) {
      return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
    }

    static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
      Map<String, T> beansMap =
          BeanFactoryUtils.beansOfTypeIncludingAncestors(
              httpSecurity.getSharedObject(ApplicationContext.class), type);
      if (beansMap.size() > 1) {
        throw new NoUniqueBeanDefinitionException(
            type,
            beansMap.size(),
            "Expected single matching bean of type '"
                + type.getName()
                + "' but found "
                + beansMap.size()
                + ": "
                + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
      }
      return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }
  }
}
