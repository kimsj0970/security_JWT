package io.security_JWT.backend.user.repository;

import io.security_JWT.backend.user.domain.RefreshToken;
import io.security_JWT.backend.user.domain.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findRefreshTokenByUser(User user);

}
