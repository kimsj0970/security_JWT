package io.security_JWT.backend.user.dto;

import lombok.Builder;

@Builder

public record Delete(String refreshToken, String email, String password) {
}
