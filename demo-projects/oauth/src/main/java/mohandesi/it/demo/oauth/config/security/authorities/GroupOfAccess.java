package mohandesi.it.demo.oauth.config.security.authorities;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class GroupOfAccess {

  private GroupOfAccess parentGroup;
  private Set<Access> additionalAccesses;
  private Set<Access> accesses;

  public GroupOfAccess(GroupOfAccess parentGroup, Set<Access> additionalAccesses) {
    this.parentGroup = parentGroup;
    this.additionalAccesses = additionalAccesses;
    this.accesses = parentGroup.getAccesses();
    this.addAccesses(additionalAccesses);
  }

  public GroupOfAccess(Set<Access> accesses) {
    this.parentGroup = null;
    this.accesses = accesses;
  }

  public GroupOfAccess(Access... accesses) {
    this.addAccesses(accesses);
  }

  public Set<Access> getAccesses() {
    return this.accesses;
  }

  public void addAccesses(Access... accesses) {
    for (Access a : accesses) {
      this.accesses.add(a);
    }
  }

  public void addAccesses(Set<Access> accesses) {
    for (Access a : accesses) {
      this.accesses.add(a);
    }
  }
}
