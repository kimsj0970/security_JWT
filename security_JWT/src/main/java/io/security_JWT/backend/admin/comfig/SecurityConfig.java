package io.security_JWT.backend.admin.comfig;

import io.security_JWT.backend.admin.Repository.BlackListRepository;
import io.security_JWT.backend.admin.app.AdminService;
import io.security_JWT.backend.admin.app.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtTokenProvider jwtTokenProvider,
            AdminService adminService,
            BlackListRepository blackListRepository
    ) throws Exception {
        JwtAuthFilter jwtAuthFilter = new JwtAuthFilter(jwtTokenProvider, adminService, blackListRepository);

        return http
                .formLogin(form->form.disable())
                .csrf(csrf -> csrf.disable())


                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    //config.setAllowedOrigins(List.of("http://localhost:5173")); // ✅ 프론트엔드 도메인
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowedHeaders(List.of("*"));
                    config.setExposedHeaders(List.of("Authorization", "Refresh")); //
                    config.setAllowCredentials(true);
                    return config;
                }))


                .httpBasic(httpBasic->httpBasic.disable())
                .authorizeHttpRequests(auth ->{auth
                        .requestMatchers("/login","/signup","/products/**","/reissue-token","/orders/**","/payment/**").permitAll()
                        .requestMatchers("/admin/**")
                        .hasRole("ADMIN")

                        .anyRequest().authenticated();
                })

                .sessionManagement(session->session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}