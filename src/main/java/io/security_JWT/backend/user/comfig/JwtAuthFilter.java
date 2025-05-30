package io.security_JWT.backend.user.comfig;

import io.jsonwebtoken.JwtException;
import io.security_JWT.backend.global.exception.BusinessException;
import io.security_JWT.backend.global.exception.domain.ErrorCode;
import io.security_JWT.backend.user.adapter.UserDetail;
import io.security_JWT.backend.user.dto.TokenBody;
import io.security_JWT.backend.user.repository.BlackListRepository;
import io.security_JWT.backend.user.app.UserService;
import io.security_JWT.backend.user.app.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Date;

@Slf4j

//필터 체인의 경우 빈으로 자동 등록이 되지 않아서 수동으로 등록한 상태 @RequiredArgsConstructor 불가
//요청이 들어왔을 때 한번만 동작한다
public class JwtAuthFilter extends OncePerRequestFilter {
    //토큰 제공자
    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;
    private final BlackListRepository blackListRepository;

    public JwtAuthFilter(JwtTokenProvider jwtTokenProvider, UserService userService,
        BlackListRepository blackListRepository) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userService = userService;
        this.blackListRepository = blackListRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        //나중에 쓸 일이 있을지?
        // AntPathMatcher pathMatcher = new AntPathMatcher();
        // String uri = request.getRequestURI();
        // String method = request.getMethod();

        String token = resolveToken(request); //헤더에서 토큰값 추출

        // 블랙리스트에 등록된 토큰인지 먼저 검사
        if (blackListRepository.findByInversionAccessToken(token)
            .filter(blacklist -> blacklist.getExpiration().after(new Date()))
            .isPresent()) { // 요청한 access 토큰값이 블랙리스트에 있으며 블랙리스트에 해당 토큰 만료 시간이 유효하면 true가 되어 차단함
            throw new JwtException("이 토큰은 블랙리스트에 등록되어 있으므로 사용할 수 없습니다.");
        }

        if (token != null && jwtTokenProvider.validate(token)) {

            // 토큰에서 사용자 정보를 추출
            TokenBody tokenBody = jwtTokenProvider.parseJwt(token);
            UserDetail userDetail = userService.getDetails(tokenBody.getUserId());

            if (userDetail == null) {
                throw new BusinessException(ErrorCode.USER_NOT_FOUND); //404
            }

            //사용자가 입력한 ID/PW를 UsernamePasswordAuthenticationToken으로 감쌈
            Authentication usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetail,
                token, userDetail.getAuthorities());
            //SecurityContex는 현재 HTTP 요청에 대한 인증 정보를 저장하는 곳으로 사용자 정보를 spring security가 관리 가능하게 해줌
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

            //기존 인증으로 있던 validate는 토큰이 위조되지 않았는가?, 서명은 맞는가?, 만료됐는가? 같은 기본적인 무결성 검사만 하므로 인증된 사용자란 보장은 되지 않음
            // Spring Security의 필터 체인은 여전히 "이 요청은 인증된 사용자 인지 물어보기 때문에 spring에게 이 사용자는 인증이 되었음을 알려 필터 체인을 통과시킨다
        }
        filterChain.doFilter(request, response);
    }

    //요청을 받아서 헤더가 있다면 "해더에서" 토큰을 추출하는 용도
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        log.debug("Bearer token: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
