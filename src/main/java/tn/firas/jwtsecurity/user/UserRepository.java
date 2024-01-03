package tn.firas.jwtsecurity.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {
//this method will will try to retrieve or find a user by email
// because email is unique so we need to find
// or we need to fetch a user by its email.
    Optional<User> findByEmail(String email);

}
