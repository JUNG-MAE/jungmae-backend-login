package login.jungmae.login.controller;

import jakarta.servlet.http.HttpServletRequest;
import login.jungmae.login.config.auth.PrincipalDetails;
import login.jungmae.login.domain.User;
import login.jungmae.login.domain.dto.TokenDto;
import login.jungmae.login.domain.dto.UserDto;
import login.jungmae.login.service.UserService;
import login.jungmae.login.domain.oauth.NaverTokenBody;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    @Autowired
    UserService userService;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;


    @GetMapping("/oauth2/token")
    public ResponseEntity<?> loginAndGetToken(@RequestParam String code) {

        System.out.println("====컨트롤러의 loginAndGetToken 메서드 입장====");
        System.out.println("code = " + code);

        try {
            NaverTokenBody naverTokenBody = userService.getAccessToken(code);
            System.out.println("naverTokenBody = " + naverTokenBody);

            //String jwtToken =
            TokenDto tokenDto = userService.saveAndGetToken(naverTokenBody.getAccess_token());

            System.out.println("====!컨트롤러의 loginAndGetToken 메서드 퇴장!====");
            return new ResponseEntity<>(tokenDto, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/oauth2/user")
    public ResponseEntity<?> getUser(HttpServletRequest request) {

        System.out.println("AccessToken = " + request.getHeader("Authorization"));

        String accessToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        UserDto userDto = null;

        try {
            userDto = userService.getUser(accessToken);
            System.out.println("userDto = " + userDto.toString());
            System.out.println("200 성공 반환");
            return new ResponseEntity<>(userDto, HttpStatus.OK);
        } catch (NullPointerException e) {
            // 엑세스 토큰이 만료되었으므로 유효하지 않은 요청으므로 401 상태를 반환
            System.out.println("401에러 반환");
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    @GetMapping("/oauth2/token/restore")
    public ResponseEntity<?> restoreAccessToken(HttpServletRequest request) {
        System.out.println("RefreshToken = " + request.getHeader("Authorization"));
        String refreshToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        String accessToken = null;

        accessToken = userService.restoreAccessToken(refreshToken);

        System.out.println("restore access token = " + accessToken);
        return new ResponseEntity<>(accessToken, HttpStatus.OK);
    }

}
