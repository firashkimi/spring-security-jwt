package tn.firas.springboot3jwtsecurity.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {

    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),
    USER_READ("utilisateur:read"),
    USER_UPDATE("utilisateur:update"),
    USER_CREATE("utilisateur:create"),
    USER_DELETE("utilisateur:delete")

    ;

    @Getter
    private final String permission;
}