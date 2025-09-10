package io.security_JWT.backend.user.config;

//import io.security_JWT.backend.user.repository.BlackListRepository;
import io.security_JWT.backend.user.app.UserService;
import io.security_JWT.backend.user.app.JwtTokenProvider;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;


@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        JwtTokenProvider jwtTokenProvider,
        UserService userService
        //, BlackListRepository blackListRepository

    ) throws Exception { //예외가 발생할 수 있는 코드 뜻
        JwtAuthFilter jwtAuthFilter = new JwtAuthFilter(jwtTokenProvider, userService//, blackListRepository
        );

        return http
            .formLogin(form -> form.disable())
            .csrf(csrf -> csrf.disable())

            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("http://localhost:5173",  "https://frontend.example.com")); // ✅ 프론트엔드 도메인
                config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                config.setAllowedHeaders(List.of("*"));
                config.setExposedHeaders(List.of("Authorization", "AccessToken")); //
                config.setAllowCredentials(true);
                return config;
            }))

            .httpBasic(httpBasic -> httpBasic.disable())
            .authorizeHttpRequests(auth -> {
                auth
                    ///reissue-token을 호출하는 시점에는 엑세스 토큰이 이미 만료되어 있으니 넣어야 함
                    .requestMatchers("/user/login", "/user/signup", "/user/reissue-token,","/user/logout").permitAll()
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    // .requestMatchers(HttpMethod.GET, "/books/**").permitAll()
                    // 책의 get 요청은 권한 없는 사람들도 접근 가능하게 하는 예시
                    .requestMatchers("/viewer/**").permitAll().anyRequest()
                    .hasAnyRole("USER", "ADMIN"); //나머지 요청은 USER 또는 ADMiN 권한을 가져야 접근 가능
            })

            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}