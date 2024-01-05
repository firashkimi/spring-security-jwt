package tn.firas.jwtsecurity.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {
    ADMIN_READ("admin:read"),
    ADMIN_WRITE("admin:create"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_DELETE("admin:delete"),
    MANAGER_READ("managment:read"),
    MANAGER_WRITE("managment:create"),
    MANAGER_UPDATE("managment:update"),
    MANAGER_DELETE("managment:delete");
@Getter
private final String permission;
}
