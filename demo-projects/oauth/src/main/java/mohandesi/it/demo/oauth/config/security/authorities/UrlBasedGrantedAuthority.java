package mohandesi.it.demo.oauth.config.security.authorities;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;

public class UrlBasedGrantedAuthority implements GrantedAuthority {
  public static final Map<String, GroupOfAccess> groupOfAccessPool = new HashMap<>();

  static {
    groupOfAccessPool.put(
        "user9000",
        new GroupOfAccess(
            Access.builder().resourceServer("9000").url("/user/hello").build(),
            Access.builder().resourceServer("9000").url("/open").build()));
    groupOfAccessPool.put(
        "admin9000",
        new GroupOfAccess(
            Access.builder().resourceServer("9000").url("/admin/hello").build(),
            Access.builder().resourceServer("9000").url("/open").build()));
  }

  private GroupOfAccess accessGroup;

  public UrlBasedGrantedAuthority(GroupOfAccess accessGroup) {
    this.accessGroup = accessGroup;
  }

  public GroupOfAccess getAccessGroup() {
    return accessGroup;
  }

  public void setAccessGroup(GroupOfAccess accessGroup) {
    this.accessGroup = accessGroup;
  }

  @Override
  public String getAuthority() {
    return null;
  }
}
