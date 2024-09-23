package login.jungmae.login.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import login.jungmae.login.config.auth.PrincipalDetails;
import login.jungmae.login.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 인증 매니저로, Spring Security의 인증 과정을 관리하는 역할을 합니다.
    // UsernamePasswordAuthenticationToken을 사용하여 인증을 시도할 때 사용됩니다.
    private final AuthenticationManager authenticationManager;


    // /login 요청이 들어오면 실행되는 메서드입니다. 로그인 시도 과정이 여기서 처리됩니다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        try {

            // ObjectMapper를 사용하여 요청의 JSON 데이터를 User 객체로 변환합니다.
            ObjectMapper om = new ObjectMapper();
            // request.getInputStream()을 통해 HTTP 요청의 내용을 읽어 User 객체에 매핑합니다.
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // 추출한 username과 passwor d를 기반으로 인증 토큰을 생성합니다.
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이 과정에서 Spring Security의 UserDetailsService를 상속받은 PrincipalDetailsService가 호출되어 DB에서 사용자의 정보를 가져와 비밀번호를 검증합니다.
            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authenticaion 객체가 리턴됨
            // 즉, 토큰을 통해 로그인이 정상적으로 이행되면 -> Authentication 객체가 만들어집니다.
            // 데이터베이스에 있는 username과 password가 일치한다.
            // 인증이 성공하면 PrincipalDetails 객체가 Authentication 객체 안에 담겨 반환됩니다.
            // 중요: 이 객체는 세션에 저장되지만 JWT 기반 인증에서는 세션을 이용하지 않습니다. 다만 Spring Security의 권한 관리 때문에 필요합니다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 로그인이 되었다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료 : " + principalDetails.getUser().getUsername());   // 값이 있다면 로그인이 정상적으로 되었다는 뜻.

            System.out.println("1==================================");

            // Authentication 객체를 세션 영역에 저장해야 하고 그 방법이 객체를 return 해주는 것이다.
            // 리턴의 이유는 권한 관리를 Security가 대신 해주기 때문에 편하려고 하는 것임.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 단지 권한 처리 때문에 Session에 넣어줍니다.
            return authentication;  // 세션에 저장된다.

        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("2==================================");
        // 2. 정상인지 로그인 시도를 해봅니다. -> authenticationManager 로 로그인을 시도하면
        // -> PrincipalDetailsService가 호출됩니다. -> loadUserByUsername() 메서드 자동 실행

        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
        // 4. JWT 토큰을 만들어 응답해줍니다.
        return null;
    }

    // 이 메서드는 attemptAuthentication 메서드에서 인증이 성공했을 때 호출됩니다. 여기서 JWT 토큰을 생성하고 클라이언트에게 응답으로 전달합니다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication 실행됨. : 인증이 완료되었다는 뜻임.");

        // PrincipalDetails에서 사용자 정보 추출: authResult에서 인증된 사용자 정보를 가져옵니다.
        // 여기서 PrincipalDetails 객체를 통해 사용자의 id와 username을 얻습니다.
        PrincipalDetails principalDetails = (PrincipalDetails) authResult .getPrincipal();

        // RSA 방식은 아니고 Hash 암호방식
        String jwtToken = JWT.create()  // jwt 생성
                .withSubject("cos토큰")   // 토큰의 주제를 설정
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) // 토큰의 만료시간을 10분후로 설정
                .withClaim("id", principalDetails.getUser().getId())    // JWT의 payload에 사용자 정보(id, username)를 추가합니다.
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));    // 비밀키 "cos"를 사용해 HMAC512 알고리즘으로 서명합니다.

        // 생성된 JWT 토큰을 Authorization 헤더에 Bearer 토큰 형식으로 추가하여 클라이언트에 전송합니다.
        // 클라이언트는 이 토큰을 저장했다가 이후의 요청에서 인증 헤더에 이 토큰을 포함해 서버에 보낼 수 있습니다.
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
