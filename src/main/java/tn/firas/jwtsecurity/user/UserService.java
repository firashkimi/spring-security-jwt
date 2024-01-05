package tn.firas.jwtsecurity.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
        //casting principal to the user Object
        var user =(User)((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();
        //Check if the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())){
            throw new IllegalStateException("Wrong Password");
        }

        //Check if the new Password same as confirmation password
        if (!request.getNewPassword().equals(request.getConfirmationNewPassword())){
            throw new IllegalStateException("Confirmation Password are not the same with new password");
        }

        //update the password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        // save the new password
        userRepository.save(user);

    }
}
