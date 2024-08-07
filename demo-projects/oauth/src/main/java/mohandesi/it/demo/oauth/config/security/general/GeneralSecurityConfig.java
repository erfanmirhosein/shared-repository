package mohandesi.it.demo.oauth.config.security.general;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class GeneralSecurityConfig {

  @Bean
  @Order(0)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    http.formLogin(formLoginCustomizer -> {});

    http.authorizeHttpRequests(
        authorizeHttpRequestsCustomizer ->
            authorizeHttpRequestsCustomizer.anyRequest().authenticated());

    return http.build();
  }

  @SuppressWarnings("deprecation")
  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }
}
