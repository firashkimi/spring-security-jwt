package tn.firas.springboot3jwtsecurity.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import tn.firas.springboot3jwtsecurity.models.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);

}