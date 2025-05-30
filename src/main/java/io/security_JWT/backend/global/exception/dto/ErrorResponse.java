package io.security_JWT.backend.global.exception.dto;

import lombok.Builder;

@Builder
public record ErrorResponse(int status, String code, String message, String path) {

}
