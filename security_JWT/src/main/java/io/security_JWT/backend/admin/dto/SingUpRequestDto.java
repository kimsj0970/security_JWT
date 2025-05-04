package io.security_JWT.backend.admin.dto;


import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class SingUpRequestDto {
    private final String email;
    private final String password;
}
