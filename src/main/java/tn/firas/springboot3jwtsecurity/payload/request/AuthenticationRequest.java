package tn.firas.springboot3jwtsecurity.payload.request;

public record AuthenticationRequest(
        String email,
        String password
) {
}
