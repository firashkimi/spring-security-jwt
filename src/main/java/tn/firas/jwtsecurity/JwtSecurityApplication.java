package tn.firas.jwtsecurity;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import tn.firas.jwtsecurity.auth.AuthenticationService;
import tn.firas.jwtsecurity.auth.RegisterRequest;

import static tn.firas.jwtsecurity.user.Role.ADMIN;
import static tn.firas.jwtsecurity.user.Role.MANAGER;

@SpringBootApplication
public class JwtSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtSecurityApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(
            //inject Register Service
            AuthenticationService service
    ) {
        return args -> {
            var admin = RegisterRequest.builder()
                    .firstName("Admin")
                    .lastName("Admin")
                    .email("admin@mail.com")
                    .password("password")
                    .role(ADMIN)
                    .build();

            System.out.println("Admin token: " + service.register(admin).getAccessToken());//Print The Token For Admin

            var manager = RegisterRequest.builder()
                    .firstName("Admin")
                    .lastName("Admin")
                    .email("manager@mail.com")
                    .password("password")
                    .role(MANAGER)
                    .build();
            System.out.println("Manager token: " + service.register(manager).getAccessToken());//Print The Token For Manager
        };
    }
}
