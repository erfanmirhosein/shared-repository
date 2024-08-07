package mohandesi.it.demo.oauth.security.oauth2.user;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import mohandesi.it.demo.oauth.security.oauth2.authorities.UrlBasedGrantedAuthority;

@Configuration
public class UsersConfig {
  @Bean
  public UserDetailsService userDetailsService() {
    return new InMemoryUserDetailsManager(createDummyUsers());
  }

  private static UserDetails createUser(
      String userName, String password, GrantedAuthority... grantedAuthorities) {

    return User.withUsername(userName).password(password).authorities(grantedAuthorities).build();
  }

  private static UserDetails[] createDummyUsers() {

    UserDetails admin9000 =
        createUser(
            "admin9000",
            "admin9000",
            new UrlBasedGrantedAuthority(
                UrlBasedGrantedAuthority.groupOfAccessPool.get("admin9000")));

    UserDetails user9000 =
        createUser(
            "user9000",
            "user9000",
            new UrlBasedGrantedAuthority(
                UrlBasedGrantedAuthority.groupOfAccessPool.get("user9000")));

    return new UserDetails[] {user9000, admin9000};
  }
}
