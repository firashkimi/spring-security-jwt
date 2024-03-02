package tn.firas.springboot3jwtsecurity.services.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tn.firas.springboot3jwtsecurity.payload.request.AuthenticationRequest;
import tn.firas.springboot3jwtsecurity.payload.request.RegisterRequest;
import tn.firas.springboot3jwtsecurity.payload.response.AuthenticationResponse;

import java.io.IOException;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request);
    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}

