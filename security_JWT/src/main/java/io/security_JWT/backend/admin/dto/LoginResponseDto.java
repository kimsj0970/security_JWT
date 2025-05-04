package io.security_JWT.backend.admin.dto;


import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class LoginResponseDto {

    private final String accessToken;
    private final String refreshToken;
}
