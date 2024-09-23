package login.jungmae.login.config.service;

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

@RequiredArgsConstructor
@Service
public class UserService {

    @Autowired
    private final UserRepository userRepository;

    public String getAccessToken(String code) {
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

        System.out.println("=====서비스 부분입니다.=====");
        System.out.println("accessTokenResponse = " + accessTokenResponse);
        System.out.println("accessTokenResponse.getBody() = " + accessTokenResponse.getBody());
        System.out.println("=====!!서비스 부분 끝!!=====");

        return accessTokenResponse.getBody();
    }

}
