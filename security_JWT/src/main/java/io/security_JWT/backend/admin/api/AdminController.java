package io.security_JWT.backend.admin.api;
import io.security_JWT.backend.admin.app.AdminService;
import io.security_JWT.backend.admin.dto.LoginRequestDto;
import io.security_JWT.backend.admin.dto.RefreshTokenRequestDto;
import io.security_JWT.backend.admin.dto.SingUpRequestDto;
import io.security_JWT.backend.admin.unit.BaseResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


@RestController
@Slf4j
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @PostMapping("/signup")
    public ResponseEntity<BaseResponse<?>> signup(@RequestBody SingUpRequestDto signUpRequestDto) {
        return adminService.save(signUpRequestDto);
    }


    //반환으로 헤더에 토큰값을 넣어줘야 하니깐 HttpServletResponse
    @PostMapping("/login")
    public ResponseEntity<BaseResponse<?>> login(@RequestBody LoginRequestDto loginRequestDto , HttpServletResponse response) {
        return adminService.login(loginRequestDto, response);

    }

    //https로 사용한다 가정하에 body값으로 refresh token을 전송
    @PostMapping("/admin/logout")
    public ResponseEntity<BaseResponse<?>> logout(@RequestHeader("Authorization") String accessToken, @RequestBody RefreshTokenRequestDto refreshTokenRequestDto) {
        return adminService.logout(accessToken, refreshTokenRequestDto);
    }



    //프론트에서 access token 만료로 인해 재발급을 요청함 (본인이 가진 refresh token을 가지고 요청합니다)
    @PostMapping("/admin/reissue-token")
    public ResponseEntity<BaseResponse<?>> reissueToken(@RequestHeader("Authorization") String refreshToken, HttpServletResponse response) {
        return adminService.reissue(refreshToken, response);
    }

}
