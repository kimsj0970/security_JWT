package io.security_JWT.backend.user.dto;

import jakarta.validation.constraints.NotBlank;

public record SingUpRequestDto(
	@NotBlank(message = "닉네임은 필수 입력값입니다.") String email,

	@NotBlank(message = "닉네임은 필수 입력값입니다.") String password,

	@NotBlank(message = "닉네임은 필수 입력값입니다.") String nickname,

	@NotBlank(message = "전화번호는 필수 입력값입니다.") String phoneNumber) {
}
