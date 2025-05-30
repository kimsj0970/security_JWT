package io.security_JWT.backend.user.mapper;

import org.springframework.security.crypto.password.PasswordEncoder;

import io.security_JWT.backend.user.domain.User;
import io.security_JWT.backend.user.dto.Delete;
import io.security_JWT.backend.user.dto.DeleteUserRequestDto;
import io.security_JWT.backend.user.dto.SingUpRequestDto;

public class UserMapper {

	public static User toUser(SingUpRequestDto dto, PasswordEncoder passwordEncoder) {
		return User.builder()
			.email(dto.email())
			.password(passwordEncoder.encode(dto.password()))  // 암호화
			.nickname(dto.nickname())
			.phoneNumber(dto.phoneNumber())
			.build();
	}

	public static Delete toDelete(DeleteUserRequestDto deleteUserRequestDto) {
		return Delete.builder().email(deleteUserRequestDto.email())
			.password(deleteUserRequestDto.password())
			.refreshToken(deleteUserRequestDto.refreshToken())
			.build();
	}
}
