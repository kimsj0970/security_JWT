package io.security_JWT.backend.admin.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Getter
@AllArgsConstructor
@NoArgsConstructor

public class RefreshTokenRequestDto {
    @JsonProperty("refreshToken")
    private String refreshToken;
}
