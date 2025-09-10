package io.security_JWT.backend.user.api;

import io.security_JWT.backend.user.adapter.UserDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


/// /////////////////////////////////
//권한을 가진 admin만 통과가 되는지 테스트
@RestController
@Slf4j
public class TestController {

    @GetMapping("/admin/test")
    public String test() {
        return "test";
    }

//    // USER 권한을 가지고 통과가 되는지
//    @GetMapping("/test")
//    public String test2(@AuthenticationPrincipal UserDetail userDetail) {
//        return "user";
//    }

    // USER 권한을 가지고 통과가 되는지
    @GetMapping("/test")
    public String test2() {
        return "user";
    }

}