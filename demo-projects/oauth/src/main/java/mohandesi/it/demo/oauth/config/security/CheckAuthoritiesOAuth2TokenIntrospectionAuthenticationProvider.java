package mohandesi.it.demo.oauth.config.security;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

public class CheckAuthoritiesOAuth2TokenIntrospectionAuthenticationProvider implements AuthenticationProvider {

    private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

    private static final TypeDescriptor LIST_STRING_TYPE_DESCRIPTOR = TypeDescriptor.collection(List.class,
            TypeDescriptor.valueOf(String.class));

    private final RegisteredClientRepository registeredClientRepository;

    private final OAuth2AuthorizationService authorizationService;

    public CheckAuthoritiesOAuth2TokenIntrospectionAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = (OAuth2TokenIntrospectionAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(
                tokenIntrospectionAuthentication);

        OAuth2Authorization authorization = this.authorizationService
                .findByToken(tokenIntrospectionAuthentication.getToken(), null);
        if (authorization == null) {
            return tokenIntrospectionAuthentication;
        }

        OAuth2Authorization.Token<OAuth2Token> authorizedToken = authorization
                .getToken(tokenIntrospectionAuthentication.getToken());

        RegisteredClient authorizedClient = this.registeredClientRepository
                .findById(authorization.getRegisteredClientId());

        Map<String, Object> additionalParametersFromRequest = tokenIntrospectionAuthentication
                .getAdditionalParameters();

        if( additionalParametersFromRequest.get("realm-access") == null){
            return new OAuth2TokenIntrospectionAuthenticationToken(tokenIntrospectionAuthentication.getToken(),
                clientPrincipal, OAuth2TokenIntrospection.builder().build());
        }

            // realm-access
            Map<String, Object> tokenClaims = authorizedToken.getClaims();
            Set<String> realmAccessFromClaims = (Set) tokenClaims.get("realm-access");

            String realmAccessFromRequest = (String) additionalParametersFromRequest.get("realm-access");


                if (!realmAccessFromClaims.contains(realmAccessFromRequest)) {

                    return new OAuth2TokenIntrospectionAuthenticationToken(tokenIntrospectionAuthentication.getToken(),
                            clientPrincipal, OAuth2TokenIntrospection.builder().build());
                }




        return null;
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
            Object convertedValue = ClaimConversionService.getSharedInstance()
                    .convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
            if (convertedValue != null) {
                convertedClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, convertedValue);
            }
        }

        value = claims.get(OAuth2TokenIntrospectionClaimNames.AUD);
        if (value != null && !(value instanceof List)) {
            Object convertedValue = ClaimConversionService.getSharedInstance()
                    .convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
            if (convertedValue != null) {
                convertedClaims.put(OAuth2TokenIntrospectionClaimNames.AUD, convertedValue);
            }
        }

        return convertedClaims;
    }

    static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
        OAuth2AuthorizationService authorizationService = httpSecurity
                .getSharedObject(OAuth2AuthorizationService.class);
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
        RegisteredClientRepository registeredClientRepository = httpSecurity
                .getSharedObject(RegisteredClientRepository.class);
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
        Map<String, T> beansMap = BeanFactoryUtils
                .beansOfTypeIncludingAncestors(httpSecurity.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                    "Expected single matching bean of type '" + type.getName() + "' but found " + beansMap.size() + ": "
                            + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }

    static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
