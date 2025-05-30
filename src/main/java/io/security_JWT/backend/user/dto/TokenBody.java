package io.security_JWT.backend.user.dto;

import io.security_JWT.backend.user.domain.Role;
import lombok.Getter;
import lombok.RequiredArgsConstructor;


@Getter
@RequiredArgsConstructor
public class TokenBody {
	private Long userId;
	private String email;
	private Role role;

	public TokenBody(Long userId, String email, Role role) {
		this.userId = userId;
		this.email = email;
		this.role = role;
	}
}
