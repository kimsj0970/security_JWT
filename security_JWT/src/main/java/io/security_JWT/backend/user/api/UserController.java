package io.security_JWT.backend.user.api;
import io.security_JWT.backend.global.unit.BaseResponse;
import io.security_JWT.backend.user.app.UserService;
import io.security_JWT.backend.user.dto.DeleteUserRequestDto;
import io.security_JWT.backend.user.dto.LoginRequestDto;
import io.security_JWT.backend.user.dto.SingUpRequestDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserService userService;

    @PostMapping("/user/signup")
    public ResponseEntity<BaseResponse<Void>> signup(@RequestBody @Valid SingUpRequestDto signUpRequestDto) {
        userService.signup(signUpRequestDto);
        return BaseResponse.okOnlyStatus(HttpStatus.CREATED);//201
    }

    //반환으로 헤더에 토큰값을 넣어줘야 하니깐 HttpServletResponse
    @PostMapping("/user/login")
    public ResponseEntity<BaseResponse<Void>> login(@RequestBody @Valid LoginRequestDto loginRequestDto,
        HttpServletResponse response) {
        userService.login(loginRequestDto, response);
        return BaseResponse.okOnlyStatus(HttpStatus.OK); //200

    }


    @PostMapping("/user/logout")
    public ResponseEntity<BaseResponse<Void>> logout(@RequestHeader("Authorization") @NotBlank String accessToken
        ,HttpServletRequest request
        ,HttpServletResponse response) {
        userService.logout(accessToken, request, response);
        return BaseResponse.okOnlyStatus(HttpStatus.NO_CONTENT); //204

    }

    //프론트에서 access token 만료로 인해 재발급을 요청함 (본인이 가진 refresh token을 가지고 요청합니다)
    @PostMapping("/user/reissue-token")
    public ResponseEntity<BaseResponse<Void>> reissueToken(HttpServletRequest request
        , HttpServletResponse response) {
        userService.reissue(request, response);
        return BaseResponse.okOnlyStatus(HttpStatus.OK); //200
    }

    @DeleteMapping("/user/delete")
    public ResponseEntity<BaseResponse<Void>> deleteUser(@RequestHeader("Authorization") @NotBlank String accessToken,
        @RequestBody @Valid DeleteUserRequestDto deleteUserRequestDto,
        HttpServletRequest request, HttpServletResponse response) {
        userService.deleteUser(accessToken, deleteUserRequestDto, request, response);
        return BaseResponse.okOnlyStatus(HttpStatus.OK);
    }

}
