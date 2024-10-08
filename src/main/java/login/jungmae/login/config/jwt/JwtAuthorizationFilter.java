package login.jungmae.login.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import login.jungmae.login.config.auth.PrincipalDetails;
import login.jungmae.login.domain.User;
import login.jungmae.login.domain.dto.TokenDto;
import login.jungmae.login.repository.UserRepository;
import login.jungmae.login.service.UserService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    private UserService userService;


    // AuthenticationManager와 UserRepository를 주입받습니다.
    // AuthenticationManager: 인증을 처리하는 핵심 객체입니다. 하지만 이 필터에서는 인증 자체보다는 JWT 검증에 중점을 둡니다.
    // UserRepository: 데이터베이스에서 사용자 정보를 가져오는 데 사용됩니다. JWT 토큰에 포함된 정보를 이용해 데이터베이스에서 해당 사용자를 조회합니다.
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, UserService userService) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.userService = userService;
    }

    // 이 메서드는 필터 체인에서 필터가 작동할 때 호출됩니다. 요청에 대한 JWT 토큰을 검증하고 인증 정보를 설정하는 핵심 로직입니다.
    // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("BasicAuthenticationFilter 를 상속받은 JwtAuthorizationFilter 실행!");
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");

        TokenDto tokenDto;

        // JWT 헤더 확인: 요청의 Authorization 헤더에서 JWT 토큰을 확인합니다. 이 헤더는 보통 Bearer <JWT 토큰> 형식으로 전달됩니다.
        String accessToken = request.getHeader("ACCESS_TOKEN");
        String refreshToken = request.getHeader("REFRESH_TOKEN");
        System.out.println("accessToken = " + accessToken);
        System.out.println("refreshToken = " + refreshToken);

//        // 헤더가 있는지 확인
//        // 만약 헤더가 없거나, Bearer로 시작하지 않는다면 필터는 JWT 검증을 하지 않고 다음 필터로 넘어갑니다.
//        if (accessToken == null || !accessToken.startsWith("Bearer ")) {
//            chain.doFilter(request, response);
//            return;
//        }

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인

        // HMAC512 알고리즘을 사용하여 서명을 검증한 뒤, username을 추출합니다.
        // 이때, "cos"는 토큰 서명을 검증하는 데 사용되는 비밀 키입니다.
        String username = null;
        String restoreAccessToken = null;

        // RefreshToken이 만료되지 않았을 경우 갱신
        try {
            System.out.println("===JwtAuthorizationFilter의 try 입장!===");
            username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(accessToken).getClaim("username").asString();
            System.out.println("username = " + username);
            restoreAccessToken = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(refreshToken).getClaim("accessToken").asString();
            System.out.println("restoreAccessToken = " + restoreAccessToken);
        // RefreshToken이 만료되었을 경우 새로 발급
        } catch (TokenExpiredException e) {
            System.out.println("===JwtAuthorizationFilter의 catch 입장!===");
            String restoreUsername = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(refreshToken).getClaim("username").asString();
            if (restoreUsername != null && restoreAccessToken.equals(accessToken)) {
                User user = userRepository.findByUsername(restoreUsername).get();
                String newAccessToken = userService.createAccessToken(user);
                String newRefreshToken = userService.createRefreshToken(user, newAccessToken);

                tokenDto = new TokenDto(newAccessToken, newRefreshToken);
            }
        }


        // username이 정상적으로 존재하는 경우, 데이터베이스에서 해당 사용자를 조회합니다.
        if (username != null) {
            System.out.println("username 정상 : " + username);
            User userEntity = userRepository.findByUsername(username).get();
            System.out.println("userEntity : " + userEntity.getUsername());
            // PrincipalDetails 객체 생성: 사용자의 정보를 담고 있는 PrincipalDetails 객체를 생성합니다.
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            System.out.println("principalDetails : " + principalDetails.getUsername() + "하하하하");
            // Authentication 객체 생성: 사용자의 인증 정보를 담고 있는 Authentication 객체를 생성합니다.
            // 이 객체는 인증된 사용자를 나타내며, 스프링 시큐리티에서 권한을 검증하는 데 사용됩니다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // SecurityContextHolder: 스프링 시큐리티의 컨텍스트에 인증 정보를 저장합니다.
            // 이렇게 저장된 인증 정보는 이후 요청에서 사용되며, 인증된 사용자로서 권한이 부여됩니다.
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        // JWT 검증 및 인증 절차가 완료되면, 필터 체인을 통해 다음 필터로 넘어갑니다. 이 과정을 통해 인증이 필요한 요청이 정상적으로 처리됩니다.
        chain.doFilter(request, response);
    }
}
