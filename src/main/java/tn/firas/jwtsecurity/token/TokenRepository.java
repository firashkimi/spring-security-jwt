package tn.firas.jwtsecurity.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Integer> {
    @Query(value = """
      select t from Token t inner join User u\s
      on t.user.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
    List<Token> findAllValidTokenByUser(Integer id);
    //help us to get all the valid tokens for specific user
    //so we pass the user ID and based on that or using that we can get all the tokens
    //that belong to this user

    Optional<Token> findByToken(String token);//finding a token by the token itself
}
