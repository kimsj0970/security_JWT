package io.security_JWT.backend.admin.domain;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Entity
@NoArgsConstructor
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String refreshToken;

    @Setter
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "admin_id")
    //단방향으로 어드민과 연결
    private Admin admin;

    private LocalDateTime createdAt = LocalDateTime.now();



    @Builder
    public RefreshToken(String refreshToken, Admin admin) {
        this.refreshToken = refreshToken;
        this.admin = admin;
    }

    public void newSetRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        this.createdAt = LocalDateTime.now(); // 갱신 시간 업데이트 (옵션)
    }
}
