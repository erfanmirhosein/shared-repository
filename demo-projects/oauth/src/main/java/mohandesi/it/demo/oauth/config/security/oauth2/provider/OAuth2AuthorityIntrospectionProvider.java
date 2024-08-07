package mohandesi.it.demo.oauth.config.security.oauth2.provider;

import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

import mohandesi.it.demo.oauth.config.security.authorities.Access;
import mohandesi.it.demo.oauth.config.security.authorities.UrlBasedGrantedAuthority;

public class OAuth2AuthorityIntrospectionProvider implements AuthenticationProvider {

  private static final String GRANTED_AUTHORITIES_CLAIM_KEY = "granted-authorities";
  private static final String URL_FIELD_KEY_IN_REQUEST = "requested-url";

  private final Log logger = LogFactory.getLog(getClass());

  private final RegisteredClientRepository registeredClientRepository;

  private final OAuth2AuthorizationService authorizationService;

  public OAuth2AuthorityIntrospectionProvider(
      RegisteredClientRepository registeredClientRepository,
      OAuth2AuthorizationService authorizationService) {
    Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
    Assert.notNull(authorizationService, "authorizationService cannot be null");
    this.registeredClientRepository = registeredClientRepository;
    this.authorizationService = authorizationService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication =
        (OAuth2TokenIntrospectionAuthenticationToken) authentication;

    OAuth2ClientAuthenticationToken clientPrincipal =
        getAuthenticatedClientElseThrowInvalidClient(tokenIntrospectionAuthentication);

    OAuth2Authorization authorization =
        this.authorizationService.findByToken(tokenIntrospectionAuthentication.getToken(), null);
    if (authorization == null) {
      if (this.logger.isTraceEnabled()) {
        this.logger.trace(
            "Did not authenticate token introspection request since token was not found");
      }
      return tokenIntrospectionAuthentication;
    }

    if (this.logger.isTraceEnabled()) {
      this.logger.trace("Retrieved authorization with token");
    }

    OAuth2Authorization.Token<OAuth2Token> authorizedToken =
        authorization.getToken(tokenIntrospectionAuthentication.getToken());
    // get to this after the revocation process has been configured
    Assert.notNull(authorizedToken, "the claims of an authorized token should not be null");

    Map<String, Object> tokenClaims = authorizedToken.getClaims();
    Assert.notNull(tokenClaims, "the claims of an authorized token should not be null");
    Set<GrantedAuthority> tokenGrantedAuthorities =
        (Set) tokenClaims.get(GRANTED_AUTHORITIES_CLAIM_KEY);

    Map<String, Object> additionalParametersFromRequest =
        tokenIntrospectionAuthentication.getAdditionalParameters();
    String requestedUrl = null;
    try {
      requestedUrl = (String) additionalParametersFromRequest.get(URL_FIELD_KEY_IN_REQUEST);
      Assert.notNull(
          requestedUrl, "the requested url should be included in the introspection request");
    } catch (NullPointerException | ClassCastException | IllegalArgumentException e) {
      if (this.logger.isTraceEnabled()) {
        this.logger.trace(
            "The resource should send the requested url as a key-value with one single value(requested-url:urlString) but it has violated this so it will receive an active:false");
      }
      return new OAuth2TokenIntrospectionAuthenticationToken(
          tokenIntrospectionAuthentication.getToken(),
          clientPrincipal,
          OAuth2TokenIntrospection.builder().build());
    }

    RegisteredClient authorizedClient =
        this.registeredClientRepository.findById(authorization.getRegisteredClientId());

    String requestingResourceServerId = clientPrincipal.getRegisteredClient().getClientId();

    for (GrantedAuthority ga : tokenGrantedAuthorities) {
      Set<Access> tokenAccesses = ((UrlBasedGrantedAuthority) ga).getAccessGroup().getAccesses();
      for (Access access : tokenAccesses) {
        if (requestedUrl.equals(access.getUrl())
            && requestingResourceServerId.equals(access.getResourceServer())) {
          return null;
        }
      }
    }

    return new OAuth2TokenIntrospectionAuthenticationToken(
        tokenIntrospectionAuthentication.getToken(),
        clientPrincipal,
        OAuth2TokenIntrospection.builder().build());
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
  }

  static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
      Authentication authentication) {
    OAuth2ClientAuthenticationToken clientPrincipal = null;
    if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(
        authentication.getPrincipal().getClass())) {
      clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
    }
    if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
      return clientPrincipal;
    }
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
  }
}
