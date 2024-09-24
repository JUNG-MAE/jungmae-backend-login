package login.jungmae.login.config.service;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import login.jungmae.login.domain.User;
import login.jungmae.login.domain.oauth.NaverProfile;
import login.jungmae.login.domain.oauth.NaverTokenBody;
import login.jungmae.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.NoSuchElementException;

@RequiredArgsConstructor
@Service
public class UserService {

    @Autowired
    private final UserRepository userRepository;

    public NaverTokenBody getAccessToken(String code) {
        System.out.println("=====서비스 부분입니다.=====");

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("client_id", "FP0nQnEUGIXGn_Ur7oqm");
        map.add("redirect_uri", "http://localhost:8080/login/oauth2/code/naver");
        map.add("code", code);
        map.add("client_secret", "yJEZHNMrSs");

        HttpEntity<MultiValueMap<String, String>> naverTokenRequest =
                new HttpEntity<>(map, headers);

        ResponseEntity<String> accessTokenResponse = restTemplate.exchange(
                "https://nid.naver.com/oauth2.0/token",
                HttpMethod.POST,
                naverTokenRequest,
                String.class
        );

        ObjectMapper objectMapper = new ObjectMapper();
        NaverTokenBody naverTokenBody = null;

        try {
            naverTokenBody = objectMapper.readValue(accessTokenResponse.getBody(), NaverTokenBody.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        System.out.println("accessTokenResponse = " + accessTokenResponse);
        System.out.println("accessTokenResponse.getBody() = " + accessTokenResponse.getBody());
        System.out.println("=====!!서비스 부분 끝!!=====");

        return naverTokenBody;
    }

    public NaverProfile getProfile(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        HttpEntity<MultiValueMap<String, String>> naverProfileRequest = new HttpEntity<>(headers);

        // 위에서 작성한 엑세스토큰을 포함한 헤더 데이터를 가진 Http Post 요청으로 네이버 프로필을 응답받는다.
        ResponseEntity<String> naverProfileResponse = restTemplate.exchange(
                "https://openapi.naver.com/v1/nid/me",
                HttpMethod.POST,
                naverProfileRequest,
                String.class
        );
        System.out.println("naverProfileResponse = " + naverProfileResponse);
        System.out.println("naverProfileResponse.getBody() = " + naverProfileResponse.getBody());

        ObjectMapper objectMapper = new ObjectMapper();
        NaverProfile naverProfile = null;

        try {
            naverProfile = objectMapper.readValue(naverProfileResponse.getBody(), NaverProfile.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return naverProfile;
    }

    public String saveAndGetToken(String accessToken) {

        System.out.println("=== saveAndGetToken 메서드 입장 ===");

        // 엑세스 토큰을 사용해 유저 프로필정보를 가져옴.
        NaverProfile naverProfile = getProfile(accessToken);
        System.out.println("naverProfile = " + naverProfile);

        User user = null;
        String username = "naver_" + naverProfile.getResponse().id;

        // 이미 회원가입이 되어 있다면 유저정보를 불러오고, 첫 로그인이면 회원가입 진행.
        try {
            user = userRepository.findByUsername(username);
        } catch (NoSuchElementException e) {
            user = User.builder()
                    .username(username)
                    .name(naverProfile.getResponse().name)
                    .email(naverProfile.getResponse().email)
                    .role("ROLE_USER")
                    .build();
            userRepository.save(user);
        }

        return createToken(user);
    }

    public String createToken(User user) {

//        String jwtToken = JWT.create()
//                .withSubject();

        return null;
    }

}
