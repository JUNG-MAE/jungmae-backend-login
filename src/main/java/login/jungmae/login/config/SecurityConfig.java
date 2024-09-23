package login.jungmae.login.config;

import login.jungmae.login.config.jwt.JwtAuthenticationFilter;
import login.jungmae.login.config.jwt.JwtAuthorizationFilter;
import login.jungmae.login.config.oauth.PrincipalOauth2UserService;
import login.jungmae.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    // 이 메서드는 스프링 컨테이너에 AuthenticationManager를 빈으로 등록하여, 다른 곳에서 인증 관련 처리를 할 수 있게 합니다.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        http.addFilter(corsFilter);
//        // OAuth2 로그인 페이지: /loginForm 경로를 사용.
//        http.oauth2Login(oauth2 -> oauth2
//                .loginPage("/loginForm")    // 구글 로그인 완료된 뒤의 후처리가 필요하다. // Tip. 코드를 받지 X, 엑세스토큰+사용자프로필 정보를 받는다.
//                .userInfoEndpoint(userinfoEndpoint -> userinfoEndpoint  // 사용자 정보 처리: OAuth2 인증이 성공한 후에 PrincipalOauth2UserService가 사용자 정보를 처리합니다.
//                        .userService(principalOauth2UserService))
//        );
        http.httpBasic(AbstractHttpConfigurer::disable);

        http.addFilter(new JwtAuthenticationFilter(authenticationManager));
        http.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));

        http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                .requestMatchers("api/v1/user/**").hasAnyRole("USER","MANAGER","ADMIN")
                .requestMatchers("api/v1/manager/**").hasAnyRole("MANAGER","ADMIN")
                .requestMatchers("api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
        );

        return http.build();
    }
}
