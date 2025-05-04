package io.security_JWT.backend.admin.dto;

import io.security_JWT.backend.admin.domain.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenBody {
    private Long adminId;
    private Role role;
}
