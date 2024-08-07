package mohandesi.it.demo.oauth.security.oauth2.authorities;

import java.util.HashSet;
import java.util.Set;

public class GroupOfAccess {

  private GroupOfAccess parentGroup;
  private Set<Access> additionalAccesses;
  private Set<Access> accesses = new HashSet<>();

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

  // the next two methods could most likely be done better but this is just a demo so...will addAll
  // entirely fail when
  // one of the additions already exists in the initial set??

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
