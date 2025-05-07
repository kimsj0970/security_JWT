package io.security_JWT.backend.admin.dto;


import io.security_JWT.backend.admin.domain.Admin;
import io.security_JWT.backend.admin.domain.Role;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Accessors(chain = true)
@Getter
@NoArgsConstructor
//구현 필수 메서드
public class AdminDetails implements UserDetails {

    private Long id;
    private String email;
    private String password;
    private Role role;

    @Builder
    public AdminDetails(String password, String email, Role role) {
        this.password = password;
        this.email = email;
        this.role = role;
    }

    public static AdminDetails AdminDetailsMake(Admin findAdmin) {
        AdminDetails adminDetails = new AdminDetails();
        adminDetails.email = findAdmin.getEmail();
        adminDetails.password = findAdmin.getPassword();
        adminDetails.role = findAdmin.getRole();
        return adminDetails;
    }

    //인가 검사 시 사용하는 것, 로그인한 사용자(Principal)의 권한(Role)을 설정하는 메서드
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of( new SimpleGrantedAuthority("ROLE_"+this.role));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    //멤버로서 만들어지는 멤버 디테일
    public static AdminDetails admindetails (Admin admin) {
        AdminDetails admindetails = new AdminDetails();
        admindetails.email = admin.getEmail();
        admindetails.role = admin.getRole();
        return admindetails;
    }


}

