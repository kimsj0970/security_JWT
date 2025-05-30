package io.security_JWT.backend.global.exception.handler;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.security_JWT.backend.global.exception.BusinessException;
import io.security_JWT.backend.global.exception.domain.ErrorCode;
import io.security_JWT.backend.global.exception.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {

	/**
	 * 비즈니스 로직에서 발생한 예외 처리 (ErrorCode 기반)
	 */
	@ExceptionHandler(BusinessException.class)
	public ResponseEntity<ErrorResponse> handleBusinessException(BusinessException e, HttpServletRequest request) {
		ErrorCode code = e.getErrorCode();

		String path = request.getMethod() + " " + request.getRequestURI();

		return ResponseEntity.status(code.getStatus()).body(ErrorResponse.builder()
			.status(code.getStatus().value())
			.code(code.name())
			.message(code.getMessage())
			.path(path)
			.build());
	}


}
