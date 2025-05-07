package io.security_JWT.backend.admin.app;

import io.security_JWT.backend.admin.dto.AdminDetails;
import io.security_JWT.backend.admin.unit.BaseResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

//알아서 admin 추출되게 만들어야 함

@Component
public class AdminContextService {

    public Long getCurrentAdminId() throws Exception {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof AdminDetails)) {
            throw new Exception("에러");
        }
        AdminDetails adminDetails = (AdminDetails) auth.getPrincipal();
        return adminDetails.getId();
    }
}
