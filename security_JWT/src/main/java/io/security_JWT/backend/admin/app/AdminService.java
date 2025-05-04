package io.security_JWT.backend.admin.app;
import io.security_JWT.backend.admin.Repository.AdminRepository;
import io.security_JWT.backend.admin.Repository.BlackListRepository;
import io.security_JWT.backend.admin.Repository.TokenRepository;
import io.security_JWT.backend.admin.domain.Admin;
import io.security_JWT.backend.admin.domain.BlackList;
import io.security_JWT.backend.admin.domain.RefreshToken;
import io.security_JWT.backend.admin.dto.AdminDetails;
import io.security_JWT.backend.admin.dto.LoginRequestDto;
import io.security_JWT.backend.admin.dto.LoginResponseDto;
import io.security_JWT.backend.admin.dto.SingUpRequestDto;
import io.security_JWT.backend.admin.unit.BaseResponse;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AdminService {

    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenRepository tokenRepository;
    private final BlackListRepository blackListRepository;


    //암호화 후 db에 회원가입 정보 저장
    //BaseResponse로 지정한 내용에 http 상태 코드를 수정 후 다시 ResponseEntity로 감싸서 보냄
    public ResponseEntity<BaseResponse<?>> save(SingUpRequestDto dto) {
        if (adminRepository.findByEmail(dto.getEmail()).isPresent()) {
            return BaseResponse.error("이미 존재하는 이메일입니다.", HttpStatus.CONFLICT); //409 반환
        }

        Admin admin = Admin.builder()
                .email(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .build();
        adminRepository.save(admin);
        return BaseResponse.ok("회원가입을 성공하셨습니다", HttpStatus.CREATED); //201 반환
    }


    //admin id값으로 admin 객체 반환
    public Optional<Admin> findById(Long id) {
        return adminRepository.findById(id);
    }

    //가져온 객체가 없으면 에러, 있으면 admin 반환
    public Admin getById(Long id){
        return findById(id).orElseThrow(
                ()-> new NoSuchElementException() );
    }

    // admin 객체를 AdminDetail로 변환
    public AdminDetails getDetails(Long id) {
        Admin findAdmin = getById(id);
        return AdminDetails.AdminDetailsMake(findAdmin);
    }



    public ResponseEntity<BaseResponse<?>> login(LoginRequestDto dto, HttpServletResponse response) {

       ///SecurityContextHolder의 경우 서버가 세션을 기억함 → 상태ful 방식이지만 JWT는  stateless 구조를 전제로 하므로 사용하지 않았음

        //가입된 email과 password가 같은지 확인
        Optional<Admin> findadmin = adminRepository.findByEmail(dto.getEmail());

        if (findadmin.isEmpty()) {                                                              //이메일이 존재하지 않다 반환 시 찾을 때까지 이메일 무한 입력 가능성
            return BaseResponse.error("계정이 존재하지 않습니다.", HttpStatus.BAD_REQUEST); //400 반환
        }

        Admin admin = findadmin.get();

        if(!passwordEncoder.matches(dto.getPassword(), admin.getPassword())){
            return BaseResponse.error("계정이 존재하지 않습니다.", HttpStatus.BAD_REQUEST);
        }

        //가입된 정보가 일치하고 db에 refresh token이 존재하고 있으면 기간이 만료된게 확인되면 다시 재발급
        String refreshToken ;
        //null이든 뭐든 사용자 정보로 db에서 refresh token이 존재하는지 검색
        Optional<RefreshToken> optionalSavedToken = tokenRepository.findByAdminId(admin.getId());
        if(optionalSavedToken.isPresent()){
            RefreshToken savedToken = optionalSavedToken.get();
            if(!jwtTokenProvider.validate(savedToken.getRefreshToken())){
                //refresh token이 존재하지만 시간이 만료된 경우 발급 및 갱신
                refreshToken = jwtTokenProvider.issueRefreshToken(admin.getId(), admin.getRole());
                savedToken.newSetRefreshToken(refreshToken);
            }else {
                //refresh token이 존재하며 유효기간도 아직 유효한 경우 기존 토큰 재사용
                refreshToken = savedToken.getRefreshToken();
            }
        }else {
            //아예 토큰이 존재하지 않았던 경우로 새로 발급 및 저장
            refreshToken = jwtTokenProvider.issueRefreshToken(admin.getId(), admin.getRole());
            tokenRepository.save(new RefreshToken(refreshToken, admin));
        }

        String accessToken = jwtTokenProvider.issueAccessToken(admin.getId(), admin.getRole());

        //재발급 후 다시헤더에 넣어서 반환
        LoginResponseDto loginResponseDto = new LoginResponseDto(accessToken, refreshToken);
        response.setHeader("Authorization", "Bearer " + loginResponseDto.getAccessToken());
        response.setHeader("Refresh", loginResponseDto.getRefreshToken());
        return BaseResponse.ok("로그인 성공", HttpStatus.OK);

    }


    // Access Token 만료 시 Refresh Token으로 재발급하는 코드
    public ResponseEntity<BaseResponse<?>> reissue(String refreshToken, HttpServletResponse response) {
        if (refreshToken.startsWith("Bearer ")) {
            refreshToken = refreshToken.substring(7);
        }

        // 토큰 유효성 확인 및 정보 추출 (사용자에 대한 권한이 아닌 토큰에 대한 유효성만 검사를 하므로 밑 부분처럼 추가 검사들이 필요합니다.)
        if (!jwtTokenProvider.validate(refreshToken)) {
            throw new IllegalArgumentException("Refresh Token이 유효하지 않습니다.");
        }

        //요청을 한 사람이 기존에 회원가입이 되어 있는 관리자가 맞는지 검사
        Long adminId = jwtTokenProvider.parseJwt(refreshToken).getAdminId();
        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(() -> new NoSuchElementException("관리자 정보를 찾을 수 없습니다."));

        // DB의 RefreshToken과 일치 여부 확인으로 클라이언트가 서버로 refresh token을 보냈을 때, 이 토큰이 서버에서 발급한 것이 맞는지 검증합니다
        RefreshToken saved = tokenRepository.findByAdminId(adminId)
                .orElseThrow(() -> new IllegalArgumentException("저장된 RefreshToken이 없습니다."));

        //위에서 가져온 admin에 맞는 토큰 정보와 클라이언트가 요청겸 가져온 refresh Token이 같은지 다른지 확인해 위조 가능성을 체크
        if (!saved.getRefreshToken().equals(refreshToken)) {
            throw new IllegalArgumentException("RefreshToken 불일치 (위조 가능성!!!)");
        }

        //Refresh token이 유효하지만 access token 재발급 용도로 사용 후
        //Refresh Token이 노출되었을 수 있기 때문에, 사용 후에는 새로운 것으로 갱신하는 것이 안전하다 합니다   (그렇대요 여쭤봐야 함)
        String newAccessToken = jwtTokenProvider.issueAccessToken(admin.getId(), admin.getRole());
        String newRefreshToken = jwtTokenProvider.issueRefreshToken(admin.getId(), admin.getRole());

        saved.newSetRefreshToken(newRefreshToken); // 새로 토큰을 발급 받아 기존 refresh token을 갱신
        LoginResponseDto loginResponseDto = new LoginResponseDto(newAccessToken, newRefreshToken);// 클라이언트에게 보내줄 용도

        response.setHeader("Authorization", "Bearer " + loginResponseDto.getAccessToken());
        response.setHeader("Refresh", loginResponseDto.getRefreshToken());
        return BaseResponse.ok("재발급 성공", HttpStatus.OK);
    }


    public ResponseEntity<BaseResponse<?>> logout(String accessToken ) {
        //토큰 구조 먼저 확인
        if (accessToken.startsWith("Bearer ")) {
            accessToken = accessToken.substring(7);
        }

        if (jwtTokenProvider.validate(accessToken)) {
            //토큰이 유효하다면, 이 토큰의 만료 시각을 가져온다. 블랙리스트에도 해당 만료 시간을 똑같이 넣어서 15분이면 15분 동안은 이 토큰을 사용하기 위해
            Date expiration = jwtTokenProvider.getExpiration(accessToken); //만료 시간 추출해서 현재 시간이 만료가 예정된 시간보다 작으면 그 토큰을 사용하지 못하게

            blackListRepository.save(new BlackList(accessToken, expiration));

        }

        return BaseResponse.ok("로그아웃 성공", HttpStatus.NO_CONTENT); //반환이 없으므로 204
    }

}
