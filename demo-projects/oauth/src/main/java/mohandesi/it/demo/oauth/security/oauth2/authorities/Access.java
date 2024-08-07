package mohandesi.it.demo.oauth.security.oauth2.authorities;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@EqualsAndHashCode
public class Access {
  private String resourceServer;
  private String url;
}
