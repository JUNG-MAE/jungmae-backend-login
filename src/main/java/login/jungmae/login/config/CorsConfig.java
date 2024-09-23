package login.jungmae.login.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");   // 모든 ip에 응답을 허용
        config.addAllowedHeader("*");   // 모든 header에 응답을 허용
        config.addAllowedMethod("*");   // 모든 post, get, put, delete, patch 요청을 허용

        // 이 부분은 /api/**로 시작하는 모든 경로에 대해 앞서 정의한 CORS 규칙을 적용합니다.
        // 예를 들어, /api/v1/user, /api/v1/manager 같은 경로는 모두 이 CORS 정책을 따릅니다.
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
