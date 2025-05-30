package io.security_JWT.backend.admin.dto;


import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class SingUpRequestDto {
    private final String email;
    private final String password;
}
