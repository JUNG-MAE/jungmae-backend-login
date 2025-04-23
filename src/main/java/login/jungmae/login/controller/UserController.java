package login.jungmae.login.controller;

import com.auth0.jwt.exceptions.TokenExpiredException;
import jakarta.servlet.http.HttpServletRequest;
import login.jungmae.login.config.auth.PrincipalDetails;
import login.jungmae.login.config.exception.InvalidTokenException;
import login.jungmae.login.config.exception.UserNotFoundException;
import login.jungmae.login.domain.User;
import login.jungmae.login.domain.dto.TokenDto;
import login.jungmae.login.domain.dto.UserDto;
import login.jungmae.login.service.UserService;
import login.jungmae.login.domain.oauth.NaverTokenBody;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor    // 생성자주입
public class UserController {

    private final Environment env;
    private final UserService userService;


//    // 안드로이드 code access 불가로 인한 주석처리
//    // code기반 로그인 구현 → accessKey기반 로그인 구현으로 수정
//    @PostMapping("/oauth2/token")
//    public ResponseEntity<?> loginAndGetToken(@RequestParam String code) {
//
//        System.out.println("====컨트롤러의 loginAndGetToken 메서드 입장====");
//        System.out.println("code = " + code);
//
//        try {
//            NaverTokenBody naverTokenBody = userService.getAccessToken(code);
//            System.out.println("naverTokenBody = " + naverTokenBody);
//            TokenDto tokenDto = userService.saveAndGetToken(naverTokenBody.getAccess_token());
//
//            System.out.println("    로그인 성공!    ");
//            return new ResponseEntity<>(tokenDto, HttpStatus.OK);
//        } catch (Exception e) {
//            System.out.println("    로그인 실패!!!    ");
//            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
//        }
//    }

    @GetMapping("/health-check")
    public String status() {
        return String.format("It's Working in User Service on Port: %s", env.getProperty("local.server.port"));
    }

    @PostMapping("/oauth2/token/test")
    public ResponseEntity<?> getAuthAccessToken(@RequestParam String code) {

        System.out.println("====컨트롤러의 loginAndGetToken 메서드 입장====");
        System.out.println("code = " + code);

        try {
            NaverTokenBody naverTokenBody = userService.getAccessToken(code);
            System.out.println("naverTokenBody = " + naverTokenBody);

            System.out.println("    auth AccessToken 발급 성공!    ");
            return new ResponseEntity<>(naverTokenBody.getAccess_token(), HttpStatus.OK);
        } catch (Exception e) {
            System.out.println("    auth AccessToken 발급 실패!!!    ");
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/oauth2/token")
    public ResponseEntity<?> loginAndGetToken(HttpServletRequest request) {

        System.out.println("====컨트롤러의 loginAndGetToken 메서드 입장====");
        System.out.println("AccessToken = " + request.getHeader("Authorization"));
        String authorization = request.getHeader("Authorization");
        String accessToken = authorization.split(" ")[1];   // Bearer를 제외한 토큰값만 할당

        try {
            TokenDto tokenDto = userService.saveAndGetToken(accessToken);

            System.out.println("    로그인 성공!    ");
            return new ResponseEntity<>(tokenDto, HttpStatus.OK);
        } catch (Exception e) {
            System.out.println("    로그인 실패!!!   ");
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


    @GetMapping("/oauth2/user")
    public ResponseEntity<?> getUser(HttpServletRequest request) {

        System.out.println("AccessToken = " + request.getHeader("Authorization"));

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        UserDto userDto = null;

        // Authorization 헤더가 없거나 형식이 잘못된 경우 처리 -> 400 BAD_REQUEST
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("Invalid Authorization header");
            return new ResponseEntity<>("Invalid Authorization header", HttpStatus.BAD_REQUEST);
        }

        String accessToken = authorization.split(" ")[1];

        // 성공
        try {
            userDto = userService.getUser(accessToken);
            System.out.println("userDto = " + userDto.toString());
            System.out.println("200 성공 반환");
            return new ResponseEntity<>(userDto, HttpStatus.OK);
        // 토큰 만료 오류
        } catch (TokenExpiredException e) {
            // 엑세스 토큰이 만료되었으므로 유효하지 않은 요청으므로 401 상태를 반환
            System.out.println("accessToken expired     ->     401에러 반환");
            return new ResponseEntity<>("accessToken expired", HttpStatus.UNAUTHORIZED);
        // 유저 정보 없음
        } catch (UserNotFoundException e) {
            // 서버에서 처리는 성공하였으나 반환할 유저 정보가 없으므로 204 상태 반환
            System.out.println("유저 정보가 없음     ->     204성공 반환");
            return new ResponseEntity<>("유저 정보가 없습니다.", HttpStatus.NO_CONTENT);
        } catch (InvalidTokenException e)  {
            System.out.println("Invalid Access Token    ->    400에러 반환");
            return new ResponseEntity<>("Invalid Access Token", HttpStatus.BAD_REQUEST);
        // 서버 오류
        } catch (Exception e) {
            // 예기치 못한 서버 오류
            System.out.println("예기치 못한 서버오류     ->     500에러 반환");
            return new ResponseEntity<>("Internal Server Error", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/oauth2/token/restore")
    public ResponseEntity<?> restoreToken(HttpServletRequest request) {
        System.out.println("RefreshToken = " + request.getHeader("Authorization"));
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Authorization 헤더가 없거나 형식이 잘못된 경우 처리 -> 400 BAD_REQUEST
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("Invalid Authorization header");
            return new ResponseEntity<>("Invalid Authorization header", HttpStatus.BAD_REQUEST);
        }

        String refreshToken = authorization.split(" ")[1];
        TokenDto tokenDto;

        //성공
        try {
            tokenDto = userService.restoreAccessToken(refreshToken);
            System.out.println("반환할 restore token = " + tokenDto.toString());
            return new ResponseEntity<>(tokenDto, HttpStatus.OK);
        } catch (TokenExpiredException e) {
            System.out.println("refreshToken expired    ->    401에러 반환");
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        } catch (UserNotFoundException e) {
            // 서버에서 처리는 성공하였으나 반환할 유저 정보가 없으므로 204 상태 반환
            System.out.println("유저 정보가 없음     ->     204성공 반환");
            return new ResponseEntity<>("유저 정보가 없습니다.", HttpStatus.NO_CONTENT);
        } catch (InvalidTokenException e) {
            System.out.println("Invalid Refresh Token    ->    400에러 반환");
            return new ResponseEntity<>("Invalid Refresh Token", HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            System.out.println("Internal Server Error    ->    500에러 반환");
            return new ResponseEntity<>("Internal Server Error", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
