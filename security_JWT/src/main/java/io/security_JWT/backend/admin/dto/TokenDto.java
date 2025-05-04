package io.security_JWT.backend.admin.dto;

import lombok.*;

@Data
@RequiredArgsConstructor

public class TokenDto {
    private String accessToken;
    private String refreshToken;
}





