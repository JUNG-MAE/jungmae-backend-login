package login.jungmae.login.controller;

import login.jungmae.login.config.service.UserService;
import login.jungmae.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    @Autowired
    UserService userService;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

//    // 회원정보
//    @GetMapping("/info")
//    public ResponseEntity<?> info() {
//
//    }

    @GetMapping("/oauth2/token")
    public ResponseEntity loginAndGetToken(@RequestParam String code) {

        System.out.println("code = " + code);
        HttpHeaders headers = new HttpHeaders();
        String response = userService.getAccessToken(code);
        System.out.println("response = " + response);
        return ResponseEntity.ok().headers(headers).body("success");
    }
}
