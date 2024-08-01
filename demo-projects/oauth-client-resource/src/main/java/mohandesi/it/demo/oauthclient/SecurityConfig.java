package mohandesi.it.demo.oauthclient;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasRole("USER")
                        .anyRequest().authenticated())
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {

        // NimbusJwtDecoder jwtDecoder =
        // NimbusJwtDecoder.withIssuerLocation("http://localhost:8080").build();

        // Converter<Jwt, Collection<GrantedAuthority>> realmAccessConverter = new
        // JwtConverterIncludingAuthorities();

        // Map<String, Converter<Jwt, Collection<GrantedAuthority>>> claimTypeConverters
        // = new HashMap<>();

        // claimTypeConverters.put("realm-access", realmAccessConverter);

        // MappedJwtClaimSetConverter converter =
        // MappedJwtClaimSetConverter.withDefaults(
        // Collections.singletonMap("realm-access", claimTypeConverters));

        // jwtDecoder.setClaimSetConverter(converter);

        // return jwtDecoder;

        return JwtDecoders.fromIssuerLocation("http://localhost:8080");

    }

    /*
     * Another Way to change the Behavior of the JWTConverter
     */

    @Bean
    public JwtAuthenticationConverter jwtConverterGrantedAuthorities() {

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new JwtConverterIncludingAuthorities());
        return converter;

    }

    public final class JwtConverterIncludingAuthorities implements Converter<Jwt, Collection<GrantedAuthority>> {

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Collection<String> realmAccess = getAuthorities(jwt);

            for (String string : realmAccess) {
                System.out.println(string);
            }

            return realmAccess.stream()
                    .map(grantedAuthority -> new SimpleGrantedAuthority(grantedAuthority))
                    .collect(Collectors.toList());
        }

        private Collection<String> getAuthorities(Jwt jwt) {
            String claimName = "realm-access";

            Object realmAccess = jwt.getClaim(claimName);

            // @SuppressWarnings("unchecked")
            if (realmAccess instanceof Collection) {
                return (Collection<String>) realmAccess;
            }

            return Collections.emptySet();
        }
    }

}
