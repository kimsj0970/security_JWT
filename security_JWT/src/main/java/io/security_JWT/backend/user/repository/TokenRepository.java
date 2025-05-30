package io.security_JWT.backend.user.repository;


import io.security_JWT.backend.user.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findTop1ByUserIdOrderByIdDesc(long adminId);

    List<RefreshToken> findAllByUserId(long adminId);
}
