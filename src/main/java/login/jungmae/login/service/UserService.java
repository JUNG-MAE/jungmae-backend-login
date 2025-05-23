package login.jungmae.login.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import login.jungmae.login.config.exception.InvalidTokenException;
import login.jungmae.login.config.exception.UserNotFoundException;
import login.jungmae.login.config.jwt.JwtProperties;
import login.jungmae.login.domain.User;
import login.jungmae.login.domain.dto.TokenDto;
import login.jungmae.login.domain.dto.UserDto;
import login.jungmae.login.domain.oauth.NaverProfile;
import login.jungmae.login.domain.oauth.NaverTokenBody;
import login.jungmae.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.naming.AuthenticationException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // code기반 로그인 구현 → accessKey기반 로그인 구현으로 수정으로 인해 주석처리

    // 해당 oauth에서 받은 Authorization code를 사용해 oauth의 토큰관련 데이터를 반환
    public NaverTokenBody getAccessToken(String code) {
        System.out.println("===== Client에서 code를 받아 accessToken을 발급받는 서비스 로직입니다.=====");

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("client_id", "FP0nQnEUGIXGn_Ur7oqm");
        map.add("redirect_uri", "http://localhost:8080/login/oauth2/code/naver");
        map.add("code", code);
        map.add("client_secret", "yJEZHNMrSs");

        // naver accessToken을 발급받기 위한 데이터 구성
        HttpEntity<MultiValueMap<String, String>> naverTokenRequest =
                new HttpEntity<>(map, headers);

        // naver accessToken 발급
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

    // oauth의 엑세스 토큰을 사용해 해당 oauth의 프로필 정보를 반환
    public NaverProfile getProfile(String oauthAccessToken) {
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + oauthAccessToken);
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
        System.out.println("naverProfileResponse = " + naverProfileResponse);

        ObjectMapper objectMapper = new ObjectMapper();
        NaverProfile naverProfile = null;

        try {
            naverProfile = objectMapper.readValue(naverProfileResponse.getBody(), NaverProfile.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return naverProfile;
    }

    // 첫 로그인이라면 유저데이터 저장하고 로그인 이력이 있다면 유저정보를 가져온 뒤, accessToken과 refreshToken을 생성해서 반환
    public TokenDto saveAndGetToken(String naverAccessToken) {

        System.out.println("=== saveAndGetToken 메서드 입장 ===");

        // 엑세스 토큰을 사용해 유저 프로필정보를 가져옴.
        NaverProfile naverProfile = getProfile(naverAccessToken);
        System.out.println("naverProfile = " + naverProfile);

        User user = null;
        String provider = "naver";
        String username = provider + "_" + naverProfile.getResponse().id;
        String password = bCryptPasswordEncoder.encode("중매");

        // 이미 회원가입이 되어 있다면 유저정보를 불러오고, 첫 로그인이면 회원가입 진행.
        try {
            // Optional을 사용해 try-catch 활용함.
            user = userRepository.findByUsername(username).get();
            System.out.println("유저가 이미 등록되어 있어서 저장하지 않고 유저정보를 불러옴.");
        } catch (NoSuchElementException e) {
            user = User.builder()
                    .username(username)
                    .name(naverProfile.getResponse().name)
                    .password(password)
                    .email(naverProfile.getResponse().email)
                    .role("ROLE_USER")
                    .provider(provider)
                    .createDate(new Timestamp(System.currentTimeMillis()))
                    .build();
            userRepository.save(user);
        }

        System.out.println("User = " + user);
        System.out.println(user.getUsername());

        String accessToken = createAccessToken(user);
        String refreshToken = createRefreshToken(user, accessToken);

        System.out.println("===saveAndGetToken 메서드 탈출!===");
        return new TokenDto(accessToken, refreshToken);
    }

    // accessToken 생성
    public String createAccessToken(User user) {

        String jwtToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME))    // 유효시간 1분
                .withClaim("id", user.getId())
                .withClaim("username", user.getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        return "Bearer " + jwtToken;
    }

    // refreshToken 생성
    public String createRefreshToken(User user, String accessToken) {

        String jwtToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME))    // 유효시간 7일
                .withClaim("username", user.getUsername())
                .withClaim("accessToken", accessToken)
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        return "Bearer " + jwtToken;
    }

    // refreshToken으로 accessToken, refreshToken 모두 재발급
    public TokenDto restoreAccessToken(String refreshToken) {

        User user = null;
        String username = null;
        String restoreAccessToken = null;
        String restoreRefreshToken = null;

        // 토큰 형식 검증
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new InvalidTokenException("Invalid token format");
        }


        try {
            // 토큰 서명 검증 및 사용자 이름 추출
            username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
                    .build()
                    .verify(refreshToken)
                    .getClaim("username")
                    .asString();
            // 사용자 조회
            user = userRepository.findByUsername(username).get();
        } catch (TokenExpiredException e) {
            System.out.println("RefreshToken 만료!");
            throw e;
        } catch (UserNotFoundException e) {
            System.out.println("User not found!");
            throw e;
        }


        restoreAccessToken = createAccessToken(user);
        restoreRefreshToken = createRefreshToken(user, restoreAccessToken);

        return new TokenDto(restoreAccessToken, restoreRefreshToken);
    }

    // 유저 정보 반환
    public UserDto getUser(String accessToken) {

        String username = null;
        String restoreAccessToken = null;
        TokenDto tokenDto = null;

        // 토큰 형식 검증
        if (accessToken == null || accessToken.isEmpty()) {
            throw new InvalidTokenException("Invalid token format");
        }

        try {
            System.out.println("=== UserService의 getUser 메소드 try 입장! ===");
            // 엑세스 토큰 만료 검증 및 복호화하여 username get
            username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
                    .build()
                    .verify(accessToken)
                    .getClaim("username")
                    .asString();

            System.out.println("username = " + username);
            Optional<User> userOptional = userRepository.findByUsername(username);
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                System.out.println("user = " + user);
                return new UserDto(user);
            } else {    // 유저 정보가 없을 경우 예외처리
                throw new UserNotFoundException("User not found");
            }

        } catch (TokenExpiredException e) {
            System.out.println("Access Token 만료!");
            throw e;
        } catch (NullPointerException e) {
            System.out.println("유효하지 않은 토큰:  " + e.getMessage());
            throw e;
        } catch (Exception e) {
            System.out.println("토큰 검증 중 오류 발생: " + e.getMessage());
            throw e;
        }


    }

}
