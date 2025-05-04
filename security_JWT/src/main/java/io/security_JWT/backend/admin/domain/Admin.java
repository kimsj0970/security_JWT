package io.security_JWT.backend.admin.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
public class Admin {

    @Id
    @Column(name="admin_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length=40, nullable=false)
    private String email;

    @Column(length=100, nullable=false)
    private String password;

    private Role role  = Role.ADMIN;

    @Builder
    public Admin(String email, String password) {
        this.email = email;
        this.password = password;
    }

}
