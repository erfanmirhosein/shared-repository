package mohandesi.it.demo.oauth.config.security.authorities;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

public class UrlBasedGrantedAuthority implements GrantedAuthority {

  private static Map<String, Map<String, Set<String>>> globalAuthorities = new HashMap<>();

  static {
    Map<String, Set<String>> resourceEndPoints = new HashMap<>();
    Set<String> resourceUrls = new HashSet<>();

    resourceUrls.add("/user/hello");
    resourceEndPoints.put("resource9000", resourceUrls);
    globalAuthorities.put("ROLE_USER", resourceEndPoints);
    resourceEndPoints = new HashMap<>();
    resourceUrls = new HashSet<>();
    resourceUrls.add("/admin/hello");
    resourceEndPoints.put("resource9000", resourceUrls);
    globalAuthorities.put("ROLE_ADMIN", resourceEndPoints);
  }

  public static Map<String, Set<String>> getRoleEndPoints(String role) {
    return globalAuthorities.get(role);
  }

  private String role = null;
  private Map<String, Set<String>> endPointBasedAuthorities = new HashMap<>();

  public UrlBasedGrantedAuthority(String role, Map<String, Set<String>> endPointBasedAuthorities) {
    this.role = role;
    this.endPointBasedAuthorities = endPointBasedAuthorities;
  }

  public String getRole() {
    return role;
  }

  public Map<String, Set<String>> getEndPointBasedAuthorities() {
    return endPointBasedAuthorities;
  }

  @Override
  public String getAuthority() {
    return null;
  }
}
