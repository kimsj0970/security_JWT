package io.security_JWT.backend.user.app;
import static io.security_JWT.backend.global.exception.domain.ErrorCode.*;

import io.security_JWT.backend.global.exception.BusinessException;
import io.security_JWT.backend.global.exception.domain.ErrorCode;
import io.security_JWT.backend.global.unit.CookieUtils;
import io.security_JWT.backend.user.adapter.UserDetail;
import io.security_JWT.backend.user.mapper.UserMapper;
//import io.security_JWT.backend.user.repository.BlackListRepository;
import io.security_JWT.backend.user.repository.RefreshTokenRedis;
import io.security_JWT.backend.user.domain.User;
//import io.security_JWT.backend.user.domain.BlackList;
import io.security_JWT.backend.user.domain.RefreshToken;
import io.security_JWT.backend.user.dto.*;
import io.security_JWT.backend.user.repository.RefreshTokenRepository;
import io.security_JWT.backend.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRedis refreshTokenRedis;
    //private final BlackListRepository blackListRepository;
    private final UserContextService userContextService;
    private final RefreshTokenRepository refreshTokenRepository;



    @Value("${custom.jwt.exp-time.refresh}")
    private int refreshTokenTime;

    //암호화 후 db에 회원가입 정보 저장
    //BaseResponse로 지정한 내용에 http 상태 코드를 수정 후 다시 ResponseEntity로 감싸서 보냄
    @Transactional
    public void signup(SingUpRequestDto dto) {
        if (userRepository.findByEmail(dto.email()).isPresent()) {
            throw new BusinessException(EMAIL_ALREADY_EXISTS);  //409
        }
        User user = UserMapper.toUser(dto, passwordEncoder);
        userRepository.save(user);
    }


    //로그인
    @Transactional
    public void login(LoginRequestDto dto, HttpServletResponse response) {

        //가입된 email과 password가 같은지 확인
        Optional<User> findUser = userRepository.findByEmail(dto.email());

        if (findUser.isEmpty()) {  //이메일이 존재하지 않다 반환 시 찾을 때까지 이메일 무한 입력 가능성이 있으니 404 반환
            throw new BusinessException(ErrorCode.LOGIN_USER_NOT_FOUND); //404
        }

        User user = findUser.get();

        if (!passwordEncoder.matches(dto.password(), user.getPassword())) {
            throw new BusinessException(ErrorCode.LOGIN_USER_NOT_FOUND);  //404
        }

        //가입된 정보가 일치하고 db에 refreshToken이나 DB에 존재하고 있지만 기간 만료 시 다시 재발급

        // Redis 조회
        String refreshToken = getTokenRedis(String.valueOf(user.getId()));
        // DB 조회
        Optional<RefreshToken> dbToken = refreshTokenRepository.findRefreshTokenByUser(user);

        if (refreshToken == null || !jwtTokenProvider.validate(refreshToken)) {
            // Redis에 없거나 만료 → DB 유효 토큰 재사용 시도
            if (dbToken.isPresent() && jwtTokenProvider.validate(dbToken.get().getRefreshToken())) {
                refreshToken = dbToken.get().getRefreshToken();
            } else {
                // DB에도 없거나 만료시 새로 발급
                refreshToken = jwtTokenProvider.issueRefreshToken(user.getId(), user.getRole(), user.getEmail());
                dbToken.ifPresent(refreshTokenRepository::delete);
                refreshTokenRepository.save(
                    RefreshToken.builder().refreshToken(refreshToken).user(user).build()
                );
            }
        }

        String accessToken = jwtTokenProvider.issueAccessToken(user.getId(), user.getRole(), user.getEmail());

        Duration ttlTime = ttlTime(refreshToken);
        saveTokenRedis(String.valueOf(user.getId()), refreshToken, ttlTime);

        // http only 쿠키 방식으로 refresh Token을 클라이언트에게 줌
        response.setHeader("Authorization", "Bearer " + accessToken);
        CookieUtils.setRefreshTokenCookie(response, refreshToken, ttlTime);

    }

    // Access Token 만료 시 Refresh Token으로 Accesss Token을 재발급하는 코드
    @Transactional
    public void reissue(HttpServletRequest request, HttpServletResponse response, long userId) {
        // 쿠키에서 refreshToken 추출
        String refreshToken = userContextService.extractRefreshTokenFromCookie(request);
        if (refreshToken == null || refreshToken.isBlank()) throw new BusinessException(INVALID_REFRESH_TOKEN);
        if (refreshToken.startsWith("Bearer ")) {refreshToken = refreshToken.substring(7);}
        // 토큰 유효성 확인 및 정보 추출 (사용자에 대한 권한이 아닌 토큰에 대한 유효성만 검사를 하므로 밑 부분처럼 추가 검사들이 필요합니다.)
        if (!jwtTokenProvider.validate(refreshToken)) {throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN); }  //401

        //요청을 한 사람이 기존에 회원가입이 되어 있는 사용자가 맞는지 검사
        if (userRepository.findById(userId).isEmpty()) {throw new BusinessException(ErrorCode.LOGIN_USER_NOT_FOUND); } //404 반환//

            //해당 user에 대한 정보가 있다면 User 객체로 가져옴
        User user = userRepository.findById(userId).get();

        //Redis, DB에 토큰 확인
        String serverToken = getTokenRedis(String.valueOf(user.getId()));
        Optional<RefreshToken> dbToken = refreshTokenRepository.findRefreshTokenByUser(user);

        if (serverToken == null && dbToken.isPresent()) {
            serverToken = dbToken.get().getRefreshToken();
            if (serverToken == null) {
                throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);    //401 //401 반환
            }
        }

        //위에서 가져온 user 토큰 정보와 클라이언트가 요청으로 가져온 refreshToken이 같은지 다른지 확인해 위조 가능성을 체크
        if (serverToken == null || !serverToken.equals(refreshToken)) {
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }
        //Redis & DB에 refreshToken 삭제
        deleteTokenRedis(String.valueOf(user.getId()));
        dbToken.ifPresent(refreshTokenRepository::delete);

        /*RefreshToken이 유효하지만 access token 재발급 용도로 사용 후
          RefreshToken이 노출되었을 수 있기 때문에, 사용 후에는 새로운 것으로 갱신하는 것이 안전하다 */
        String newAccessToken = jwtTokenProvider.issueAccessToken(user.getId(), user.getRole(), user.getEmail());

        //새로 발급한 refreshToken Redis에 다시 저장
        String newRefreshToken = jwtTokenProvider.issueRefreshToken(user.getId(), user.getRole(), user.getEmail());

        Duration ttlTime = ttlTime(newRefreshToken);
        saveTokenRedis(String.valueOf(user.getId()), newRefreshToken, ttlTime);
        refreshTokenRepository.save(RefreshToken.builder().refreshToken(newRefreshToken).user(user).build());

        response.setHeader("Authorization", "Bearer " + newAccessToken);
        CookieUtils.setRefreshTokenCookie(response, newRefreshToken, ttlTime);

    }



    //로그아웃 = Redis에서 토큰 삭제
    // 만료 = Redis의 TTL로 자연스럽게 만료됨
    @Transactional
    public void logout(String accessToken, HttpServletRequest request, HttpServletResponse response, long userId) {

        User user = userRepository.findById(userId).orElseThrow(() -> new BusinessException(LOGIN_USER_NOT_FOUND));

        //redis에 먼저 있는지 확인
        String serverToken = getTokenRedis(String.valueOf(user.getId()));
        Optional<RefreshToken> dbToken = refreshTokenRepository.findRefreshTokenByUser(user);

        if (serverToken == null && dbToken.isPresent()) {
            serverToken = dbToken.get().getRefreshToken();
            if (serverToken == null) {
                throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);    //401 //401 반환
            }
        }

        String refreshTokenFromCookie = userContextService.extractRefreshTokenFromCookie(request);

        if (serverToken == null || !serverToken.equals(refreshTokenFromCookie)) {
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }
        /// access Token을 블랙리스트 방식으로 사용 시 사용
        //토큰이 유효하다면, 이 토큰의 만료 시각을 가져온다. 블랙리스트에도 해당 만료 시간을 똑같이 넣어서 15분이면 15분 동안은 이 토큰을 사용하기 위해
        // Date expiration = jwtTokenProvider.getExpiration(accessToken); //만료 시간 추출해서 현재 시간이 만료가 예정된 시간보다 작으면 그 토큰을 사용하지 못하게
        // blackListRepository.save(new BlackList(accessToken, expiration));

        //Redis & DB refreshToken 삭제
        deleteTokenRedis(String.valueOf(user.getId()));
        dbToken.ifPresent(refreshTokenRepository::delete);

        // 쿠키 삭제 처리
        CookieUtils.deleteRefreshTokenCookie(response);

    }

    @Transactional
    public void deleteUser(String accessToken, DeleteUserRequestDto deleteUserRequestDto
        ,HttpServletRequest request, HttpServletResponse response, long userId) {
        //토큰 구조 먼저 확인
        if (accessToken.startsWith("Bearer ")) {
            accessToken = accessToken.substring(7);
        }
        if (!jwtTokenProvider.validate(accessToken)) {throw new BusinessException(ErrorCode.INVALID_ACCESS_TOKEN);}

        Delete delete = UserMapper.toDelete(deleteUserRequestDto);

        // 1. 유저 정보 추출
        User user = userRepository.findById(userId).orElseThrow(() -> new BusinessException(LOGIN_USER_NOT_FOUND));

        // 2. DB에서 유저 조회
        User tokenUser = userRepository.findById(userId).orElseThrow(() -> new BusinessException(USER_NOT_FOUND));

        //이메일 비교
        if (!delete.email().equals(tokenUser.getEmail())) {throw new BusinessException(ErrorCode.LOGIN_USER_NOT_FOUND); } // 404


        //redis에 먼저 있는지 확인
        String serverToken = getTokenRedis(String.valueOf(user.getId()));
        Optional<RefreshToken> dbToken = refreshTokenRepository.findRefreshTokenByUser(user);

        if (serverToken == null && dbToken.isPresent()) {
            serverToken = dbToken.get().getRefreshToken();
            if (serverToken == null) {
                throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);    //401 //401 반환
            }
        }

        String refreshToken = userContextService.extractRefreshTokenFromCookie(request);
        if (serverToken == null || !serverToken.equals(refreshToken)) {
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        //비밀번호 비교
        if (!passwordEncoder.matches(delete.password(), tokenUser.getPassword())) {
            throw new BusinessException(ErrorCode.LOGIN_USER_NOT_FOUND);  //404
        }


        //refresh token DB에서 삭제
        deleteTokenRedis(String.valueOf(user.getId()));
        dbToken.ifPresent(refreshTokenRepository::delete);

        //유저 삭제
        userRepository.findById(userId).ifPresent(userRepository::delete);

        // 쿠키 삭제 처리
        CookieUtils.deleteRefreshTokenCookie(response);
    }




    public String getTokenRedis(String userId) {
        try {
            return refreshTokenRedis.getToken(userId);
        } catch (Exception e) {
            log.warn("Redis GET 실패 (DB 조회), userId={}, 에러 코드 DB: {}", userId, e.getMessage());
            return null;
        }
    }

    public void saveTokenRedis(String userId, String token, Duration ttl) {
        try {
            refreshTokenRedis.saveToken(userId, token, ttl);
        } catch (Exception e) {
            log.warn("Redis SAVE 실패 (DB 저장), userId={}, 에러 코드 {}", userId, e.getMessage());
        }
    }

    public void deleteTokenRedis(String userId) {
        try {
            refreshTokenRedis.deleteToken(userId);
        } catch (Exception e) {
            log.warn("Redis DELETE 실패, userId={}, 에러 코드 {}", userId, e.getMessage());
        }
    }

    private Duration ttlTime(String jwt) {
        long millis = jwtTokenProvider.getExpiration(jwt).getTime() - System.currentTimeMillis();
        return millis <= 0 ? Duration.ZERO : Duration.ofMillis(millis);
    }

    //user id값으로 user 객체 반환
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    //가져온 객체가 없으면 에러, 있으면 user 반환
    public User getById(Long id) {
        return findById(id).orElseThrow(() -> new BusinessException(ErrorCode.LOGIN_USER_NOT_FOUND));
    }

    // user 객체를 UserDetail로 변환
    public UserDetail getDetails(Long id) {
        User findUser = getById(id);
        return UserDetail.UserDetailsMake(findUser);
    }



}