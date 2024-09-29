package login.jungmae.login.config;


import login.jungmae.login.config.jwt.JwtAuthorizationFilter;

import login.jungmae.login.repository.UserRepository;
import login.jungmae.login.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;
    private final UserService userService;


    // 이 메서드는 스프링 컨테이너에 AuthenticationManager를 빈으로 등록하여, 다른 곳에서 인증 관련 처리를 할 수 있게 합니다.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
                // REST API 설정
                .csrf(AbstractHttpConfigurer::disable)  // csrf 비활성화 -> cookie를 사용하지 않으면 꺼도 된다. (cookie를 사용할 경우 httpOnly(XSS 방어), sameSite(CSRF 방어)로 방어해야 한다.)
                //.cors(AbstractHttpConfigurer::disable)  // cors 비활성화 -> 프론트와 연결 시 따로 설정이 필요
                .httpBasic(AbstractHttpConfigurer::disable)   // 기본 인증 로그인 비활성화
                .formLogin(AbstractHttpConfigurer::disable)   // 기본 login form 비활성화
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));   // 세션 사용하지 않음


        http.addFilter(corsFilter);
//        // OAuth2 로그인 페이지: /loginForm 경로를 사용.
//        http.oauth2Login(oauth2 -> oauth2
//                .loginPage("/loginForm")    // 구글 로그인 완료된 뒤의 후처리가 필요하다. // Tip. 코드를 받지 X, 엑세스토큰+사용자프로필 정보를 받는다.
//                .userInfoEndpoint(userinfoEndpoint -> userinfoEndpoint  // 사용자 정보 처리: OAuth2 인증이 성공한 후에 PrincipalOauth2UserService가 사용자 정보를 처리합니다.
//                        .userService(principalOauth2UserService))
//        );


//        http.addFilter(new JwtAuthenticationFilter(authenticationManager));
//        http.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository, userService));

        // request 에 대한 인증 인가 설정
        http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                .requestMatchers("oauth2/user/**").hasAnyRole("USER","ADMIN")
                .requestMatchers("oauth2/manager/**").hasRole("ADMIN")
                .requestMatchers("api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
        );

        return http.build();
    }
}
