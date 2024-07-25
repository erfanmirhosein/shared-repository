package mohandesi.it.demo.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSectChainOAuth(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.authorizeHttpRequests(
                authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                        .anyRequest().authenticated());
        httpSecurity.oauth2Login();

        return httpSecurity.build();
    }
}

// .requestMatchers("/auth/login**").permitAll()
// .requestMatchers("/unauthorized/**").permitAll()
// .anyRequest().authenticated()