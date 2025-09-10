package io.security_JWT.backend.user.repository;


import io.security_JWT.backend.user.domain.RefreshToken;
import java.time.Duration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenRedis {
    private final RedisTemplate<String,String> redisTemplate;
    private static final String REFRESH_TOKEN_KEY = "refresh_token";

    public RefreshTokenRedis(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveToken(String userId, String refreshToken, Duration duration) {
        redisTemplate.opsForValue().set(REFRESH_TOKEN_KEY + userId, refreshToken, duration);
    }

    public String getToken(String userId) {
        return redisTemplate.opsForValue().get(REFRESH_TOKEN_KEY + userId);
    }

    public void deleteToken(String userId) {
        redisTemplate.delete(REFRESH_TOKEN_KEY + userId);
    }

    public boolean findToken (String userId) {
        return redisTemplate.hasKey(REFRESH_TOKEN_KEY + userId);
    }


    public void saveToken(String userId, RefreshToken refreshToken, Duration duration) {
        redisTemplate.opsForValue().set(REFRESH_TOKEN_KEY+userId, refreshToken.getRefreshToken(), duration);
    }
}
