package io.security_JWT.backend.admin.app;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.security_JWT.backend.admin.Repository.TokenRepository;
import io.security_JWT.backend.admin.comfig.JwtConfiguration;
import io.security_JWT.backend.admin.domain.RefreshToken;
import io.security_JWT.backend.admin.domain.Role;
import io.security_JWT.backend.admin.dto.TokenBody;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
//토큰 발급하는 제공자
public class JwtTokenProvider {

    //yml에서 가져옴
    private final JwtConfiguration jwtConfiguration;
    private final TokenRepository tokenRepository;


    // JWT 토큰 서명에 쓰이는 비밀 키 문자열 생성
    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtConfiguration.getSecrets().getAppkey().getBytes());
    }

    //access 토큰 생성
    public String issueAccessToken(Long id, Role role) {
        return issueToken(id, role, jwtConfiguration.getExpTime().getAccess());
    }

    //refresh 토큰 생성
    public String issueRefreshToken(Long id, Role role) {
        return issueToken(id, role, jwtConfiguration.getExpTime().getRefresh());
    }

    //멤버가 가진 RefreshToken 가져오기
    public Optional<RefreshToken> findRefreshToken(Long adminId) {
        return tokenRepository.findByAdminId(adminId);

    }

    //access & refresh 토큰 생성
    private String issueToken(Long id, Role role, Long expTime) {
        String token = Jwts.builder()
                .subject(id.toString())
                .claim("role", role.name())
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + expTime))
                .signWith(getSecretKey(), Jwts.SIG.HS256) //문자열을 바이트로 바꿈,  서명으로 어떻게 암호화 할지
                .compact();
        return token;
    }

    // ** 토큰이 유효한지 아닌지 확인 유효성 검사로 access 토큰이 들어오든 refresh 토큰이 들어오든 상관이 없다 그저 형식, 만료 여부만 검샇 **
    public boolean validate(String token) {
        try {
            //검증용 생성
            JwtParser jwtParser = Jwts.parser()
                    //내가 만든 키가 맞는지 테스트를 위해 내 비밀키로 설정함
                    .verifyWith(getSecretKey())
                    .build();

            //이전에 설정한 시크릿 키를 가져와서 access토큰을 만든 후 만들어진 jwtparser과 token값을 비교해 토큰값이 제대로 맞는지 확인
            // 이 부분에서 서명이 변조 되었는지, 만료 시간을 현재 시간과 비교해 유효한지 판단
            jwtParser.parseSignedClaims(token);

            return true; // 성공하면 유효한 토큰이다

        } catch (ExpiredJwtException e) {
            log.warn("토큰 만료됨: {}", token);
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 토큰 형식: {}", token);
        } catch (MalformedJwtException e) {
            log.warn("구조가 잘못된 토큰: {}", token);
        } catch (SignatureException e) {
            log.warn("서명 검증 실패: {}", token);

        } catch (JwtException e) { // try 과정에서 예외가 발생하면 유효하지 않은 토큰
            log.error("{}", token);
            log.error("잘못된 토큰 입력됨");

        } catch (Exception e) {
            log.error("{}", token);
            log.error("더 이상한 오류인 상황");
        }
        return false;
    }

    // JWT "토큰에서" admin 정보 꺼내기
    public TokenBody parseJwt(String token) {
        //jwts.parset는 JWT를 해석하고 검증하기 위한 파서(parser)를 생성하는 객체
        Jws<Claims> parserd = Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token);
        String adminId = parserd.getPayload().getSubject();//admin에 대한 입력한 정보들이 나온다
        String role = parserd.getPayload().get("role").toString(); //이렇게 키 값으로 가져오기도 가능

        return new TokenBody(Long.parseLong(adminId), Role.valueOf(role));
    }


    public Date getExpiration(String accessToken) {
        return Jwts.parser().verifyWith(getSecretKey())       // 서명 검증용 키 설정
                .build()                          // JwtParser로 build 후 파싱하여 추출
                .parseSignedClaims(accessToken)   // JWT 파싱
                .getPayload()                     // Claims 객체 추출
                .getExpiration();                 // 만료 시간 추출
    }
}
