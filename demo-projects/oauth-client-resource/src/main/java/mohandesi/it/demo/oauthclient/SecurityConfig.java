package mohandesi.it.demo.oauthclient;

import java.net.URI;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, HttpServletRequest httpServletRequest) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2ResourceServerCustomizer -> oauth2ResourceServerCustomizer
                        .opaqueToken(customizer -> customizer.introspector(introspector(httpServletRequest))));

        return http.build();
    }

    // should it be a bean???
    @Bean
    public OpaqueTokenIntrospector introspector(HttpServletRequest httpServletRequest) {

        String introspectionUri = "http://localhost:8080/oauth2/introspect";
        String clientId = "resource9000";
        String clientSecret = "resource9000";
        NimbusOpaqueTokenIntrospector withAuthoritiesIntrospector = new NimbusOpaqueTokenIntrospector(introspectionUri,
                clientId, clientSecret);
        withAuthoritiesIntrospector
                .setRequestEntityConverter(
                        new WithAuthoritiesRequestEntityConverter(URI.create(introspectionUri), httpServletRequest,
                                clientId, clientSecret));

        return withAuthoritiesIntrospector;
    }

    private static class WithAuthoritiesRequestEntityConverter
            implements Converter<String, RequestEntity<?>> {

        private URI introspectionUri;
        private HttpServletRequest httpServletRequest;
        private String clientId;
        private String clientSecret;

        WithAuthoritiesRequestEntityConverter(URI introspectionUri,
                HttpServletRequest httpServletRequest, String clientId, String clientSecret) {
            this.introspectionUri = introspectionUri;
            this.httpServletRequest = httpServletRequest;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        @Override
        public RequestEntity<MultiValueMap<String, String>> convert(String token) {

            HttpHeaders headers = requestHeaders();

            MultiValueMap<String, String> body = requestBody(token);

            return new RequestEntity<>(body, headers, HttpMethod.POST,
                    this.introspectionUri);

        }

        private HttpHeaders requestHeaders() {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            headers.setBasicAuth(this.clientId, this.clientSecret);
            return headers;
        }

        private MultiValueMap<String, String> requestBody(String token) {
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", token);
            body.add("realm-access", httpServletRequest.getServletPath());
            return body;
        }

    }

}
