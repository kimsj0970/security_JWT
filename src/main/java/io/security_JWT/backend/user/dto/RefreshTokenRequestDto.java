package io.security_JWT.backend.user.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequestDto(
	@JsonProperty("refreshToken")
	@NotBlank(message = "refreshToken은 필수 입력값입나다.")
	String refreshToken) {
}

