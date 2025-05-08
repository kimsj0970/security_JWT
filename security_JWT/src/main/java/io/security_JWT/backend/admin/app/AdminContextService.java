package io.security_JWT.backend.admin.app;

import io.security_JWT.backend.admin.dto.AdminDetails;
import io.security_JWT.backend.admin.unit.BaseResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

//알아서 admin 추출되게 만들어야 함

@Component
public class AdminContextService {

    public Long getCurrentAdminId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Authentication이 null이거나, Principal이 AdminDetails가 아닌 경우 예외 처리
        if (auth == null || !(auth.getPrincipal() instanceof AdminDetails)) {
            throw new AccessDeniedException("관리자 권한이 없습니다.");
        }

        AdminDetails adminDetails = (AdminDetails) auth.getPrincipal();
        return adminDetails.getId();  // 어드민 ID 반환
    }
}