package mohandesi.it.demo.oauth.security.oauth2.provider;

import java.util.Map;
import java.util.Set;
import mohandesi.it.demo.oauth.security.oauth2.authorities.Access;
import mohandesi.it.demo.oauth.security.oauth2.authorities.UrlBasedGrantedAuthority;
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
import org.springframework.util.Assert;

public class OAuth2AuthorityIntrospectionProvider implements AuthenticationProvider {

  private static final String GRANTED_AUTHORITIES_CLAIM_KEY = "granted-authorities";
  private static final String URL_FIELD_KEY_IN_REQUEST = "requested-url";

  private final Log logger = LogFactory.getLog(getClass());

  private final OAuth2AuthorizationService authorizationService;

  public OAuth2AuthorityIntrospectionProvider(OAuth2AuthorizationService authorizationService) {
    Assert.notNull(authorizationService, "authorizationService cannot be null");
    this.authorizationService = authorizationService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication =
        (OAuth2TokenIntrospectionAuthenticationToken) authentication;

    OAuth2ClientAuthenticationToken clientPrincipal =
        getAuthenticatedClientElseThrowInvalidClient(tokenIntrospectionAuthentication);
    // if clientPrincipal was going to be null an Exception would be thrown before the next line
    String requestingResourceServerId = clientPrincipal.getRegisteredClient().getClientId();

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
    @SuppressWarnings("unchecked")
    Set<GrantedAuthority> tokenGrantedAuthorities =
        (Set<GrantedAuthority>) tokenClaims.get(GRANTED_AUTHORITIES_CLAIM_KEY);

    Map<String, Object> additionalParametersFromRequest =
        tokenIntrospectionAuthentication.getAdditionalParameters();
    String requestedUrl;
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

    for (GrantedAuthority ga : tokenGrantedAuthorities) {
      Set<Access> tokenAccesses = ((UrlBasedGrantedAuthority) ga).getAccessGroup().getAccesses();
      for (Access access : tokenAccesses) {
        if (requestedUrl.equals(access.getUrl())
            && requestingResourceServerId.equals(access.getResourceServer())) {
          if (this.logger.isTraceEnabled()) {
            this.logger.trace("The end user's access to the requested url has been confirmed");
          }
          return null;
        }
      }
    }

    if (this.logger.isTraceEnabled()) {
      this.logger.trace(
          "The end user does not have the access to the requested url so an active:false will be sent back");
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
