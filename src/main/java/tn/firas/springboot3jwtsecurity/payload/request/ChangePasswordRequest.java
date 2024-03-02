package tn.firas.springboot3jwtsecurity.payload.request;

public record ChangePasswordRequest(
        String currentPassword,
     String newPassword,
      String confirmationPassword
) {
}
