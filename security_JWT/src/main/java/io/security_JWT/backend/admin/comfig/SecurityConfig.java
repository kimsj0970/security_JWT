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
                .cors(cors -> cors.disable())
                .httpBasic(httpBasic->httpBasic.disable())
                .authorizeHttpRequests(auth ->{auth
                        .requestMatchers("/login","/signup","/products/**","/reissue-token").permitAll()
                        .requestMatchers("/admin/**")
                        .hasRole("ADMIN")
                        //나중에 다시 보기
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
