package tn.firas.springboot3jwtsecurity.services.auth;

import tn.firas.springboot3jwtsecurity.payload.request.ChangePasswordRequest;

import java.security.Principal;

public interface UserService {
    void changePassword(ChangePasswordRequest request, Principal connectedUser);
}
