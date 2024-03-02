package tn.firas.springboot3jwtsecurity.payload.request;

import lombok.Builder;
import tn.firas.springboot3jwtsecurity.enums.Role;

public record RegisterRequest(
        String firstname,
        String lastname,
        String email,
        String password,
        Role role
) {
}
