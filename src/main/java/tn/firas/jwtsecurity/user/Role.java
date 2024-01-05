package tn.firas.jwtsecurity.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static tn.firas.jwtsecurity.user.Permission.*;

@RequiredArgsConstructor
public enum Role {
    USER(Collections.EMPTY_SET),
    ADMIN(Set.of(
            ADMIN_READ,
            ADMIN_WRITE,
            ADMIN_UPDATE,
            ADMIN_DELETE,
            MANAGER_UPDATE,
            MANAGER_DELETE,
            MANAGER_READ,
            MANAGER_WRITE
    )),
    MANAGER(
            Set.of(
                 MANAGER_DELETE,
                 MANAGER_READ,
                 MANAGER_UPDATE,
                 MANAGER_WRITE
            )
    );

    @Getter
    private final Set<Permission> permissions;

    public List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))//spring will use this information to decide what who can access what and here it's gonna it's gonna be permission
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
