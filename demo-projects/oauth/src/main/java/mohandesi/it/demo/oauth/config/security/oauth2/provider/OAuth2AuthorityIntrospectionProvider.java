package mohandesi.it.demo.oauth.config.security.oauth2.provider;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.CollectionUtils;

public class OAuth2AuthorityIntrospectionProvider implements AuthenticationProvider {

  private static final String GRANTED_AUTHORITIES_CLAIM_KEY = "granted-authorities";
  private static final String URL_FIELD_KEY_IN_REQUEST = "requested-url";

  private final Log logger = LogFactory.getLog(getClass());

  private final RegisteredClientRepository registeredClientRepository;

  private final OAuth2AuthorizationService authorizationService;

  public OAuth2AuthorityIntrospectionProvider(
      RegisteredClientRepository registeredClientRepository,
      OAuth2AuthorizationService authorizationService) {
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
      return tokenIntrospectionAuthentication;
    }

    OAuth2Authorization.Token<OAuth2Token> authorizedToken =
        authorization.getToken(tokenIntrospectionAuthentication.getToken());


    try{

    }catch (){

    }

    RegisteredClient authorizedClient =
        this.registeredClientRepository.findById(authorization.getRegisteredClientId());

    Map<String, Object> additionalParametersFromRequest =
        tokenIntrospectionAuthentication.getAdditionalParameters();

    if (additionalParametersFromRequest.get(URL_FIELD_KEY_IN_REQUEST) == null) {
      return new OAuth2TokenIntrospectionAuthenticationToken(
          tokenIntrospectionAuthentication.getToken(),
          clientPrincipal,
          OAuth2TokenIntrospection.builder().build());
    }

    String realmAccessFromRequest =
        (String) additionalParametersFromRequest.get(URL_FIELD_KEY_IN_REQUEST);

    Set<GrantedAuthority> grantedAuthoritiesFromTokenClaims = Collections.emptySet();
    if (tokenClaims.get(GRANTED_AUTHORITIES_CLAIM_KEY) instanceof Set)
      grantedAuthoritiesFromTokenClaims = (Set) tokenClaims.get(GRANTED_AUTHORITIES_CLAIM_KEY);

    String realmAccessFromRequest =
        (String) additionalParametersFromRequest.get(GRANTED_AUTHORITIES_CLAIM_KEY);
    String requestingResourceServerId = clientPrincipal.getRegisteredClient().getClientId();

    //        Map<String,Set<String>>
    for (GrantedAuthority ga : realmAccessFromClaims) {
      Set<String> grantedUrls =
          ((EndPointBasedGrantedAuthority) ga)
              .getEndPointBasedAuthorities()
              .get(requestingResourceServerId);
      if (grantedUrls != null && grantedUrls.contains(realmAccessFromRequest)) {
        return null;
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

  private static OAuth2TokenIntrospection withActiveTokenClaims(
      OAuth2Authorization.Token<OAuth2Token> authorizedToken, RegisteredClient authorizedClient) {

    OAuth2TokenIntrospection.Builder tokenClaims;
    if (!CollectionUtils.isEmpty(authorizedToken.getClaims())) {
      Map<String, Object> claims = convertClaimsIfNecessary(authorizedToken.getClaims());
      tokenClaims = OAuth2TokenIntrospection.withClaims(claims).active(true);
    } else {
      tokenClaims = OAuth2TokenIntrospection.builder(true);
    }

    tokenClaims.clientId(authorizedClient.getClientId());

    // TODO Set "username"

    OAuth2Token token = authorizedToken.getToken();
    if (token.getIssuedAt() != null) {
      tokenClaims.issuedAt(token.getIssuedAt());
    }
    if (token.getExpiresAt() != null) {
      tokenClaims.expiresAt(token.getExpiresAt());
    }

    if (OAuth2AccessToken.class.isAssignableFrom(token.getClass())) {
      OAuth2AccessToken accessToken = (OAuth2AccessToken) token;
      tokenClaims.tokenType(accessToken.getTokenType().getValue());
    }

    return tokenClaims.build();
  }

  private static Map<String, Object> convertClaimsIfNecessary(Map<String, Object> claims) {
    Map<String, Object> convertedClaims = new HashMap<>(claims);

    Object value = claims.get(OAuth2TokenIntrospectionClaimNames.ISS);
    if (value != null && !(value instanceof URL)) {
      URL convertedValue = ClaimConversionService.getSharedInstance().convert(value, URL.class);
      if (convertedValue != null) {
        convertedClaims.put(OAuth2TokenIntrospectionClaimNames.ISS, convertedValue);
      }
    }

    value = claims.get(OAuth2TokenIntrospectionClaimNames.SCOPE);
    if (value != null && !(value instanceof List)) {
      Object convertedValue =
          ClaimConversionService.getSharedInstance()
              .convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
      if (convertedValue != null) {
        convertedClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, convertedValue);
      }
    }

    value = claims.get(OAuth2TokenIntrospectionClaimNames.AUD);
    if (value != null && !(value instanceof List)) {
      Object convertedValue =
          ClaimConversionService.getSharedInstance()
              .convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
      if (convertedValue != null) {
        convertedClaims.put(OAuth2TokenIntrospectionClaimNames.AUD, convertedValue);
      }
    }

    return convertedClaims;
  }

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
