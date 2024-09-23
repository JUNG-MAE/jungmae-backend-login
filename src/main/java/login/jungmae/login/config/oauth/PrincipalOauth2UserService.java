package login.jungmae.login.config.oauth;

import login.jungmae.login.config.auth.PrincipalDetails;
import login.jungmae.login.config.oauth.provider.GoogleUserInfo;
import login.jungmae.login.config.oauth.provider.NaverUserInfo;
import login.jungmae.login.config.oauth.provider.OAuth2UserInfo;
import login.jungmae.login.model.User;
import login.jungmae.login.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.NoSuchElementException;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oauth2User = super.loadUser(userRequest);

        OAuth2UserInfo oAuth2UserInfo = null;

        // GoogleUserInfo, NaverUserInfo: 각각 구글과 네이버로부터 받은 사용자 정보를 해당하는 방식으로 파싱합니다.
        // registrationId를 사용해 사용자가 구글 로그인인지 네이버 로그인을 사용했는지 확인한 후, 각기 다른 파싱 방식으로 정보를 가져옵니다.
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        }
        else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("네이버 로그인 요청");
            // naver는 response안에 유저 프로필 정보가 들어가 있어서 .get("response")까지 접근해줍니다.
            oAuth2UserInfo = new NaverUserInfo((Map)oauth2User.getAttributes().get("response"));
        }
        else {
            System.out.println("우리는 구글 로그인과 네이버 로그인만 지원합니다.");
        }

        // 업캐스팅을 사용하여 여러 OAuth 로그인을 적용시킨 코드입니다.
        // 어떤 도메인의 OAuth인지 상관없이 다 적용된다.
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;  // 구글이면 google_115670172973792303639, 네이버면 naver_7vCv6LhWKM7PBznen65Alm2dkd-uFoVCIMtF6xdY2z0
        String password = bCryptPasswordEncoder.encode("겟인데어"); // OAuth 로그인에서는 비밀번호는 의미가 없으나 필수 필드를 채우기 위해 기본 값을 넣습니다.
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";  // 기본적으로 ROLE_USER로 설정합니다.

        User userEntity = userRepository.findByUsername(username);

        // 회원 존재 여부 확인: 이미 같은 username이 존재하면 새로 회원가입을 하지 않고, 기존 회원 정보를 사용하여 로그인 처리만 합니다.
        if (userEntity == null) {
            System.out.println("로그인이 최초입니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        else {
            System.out.println("로그인을 이미 한 적이 있습니다. 당신은 자동 회원 가입이 되어 있습니다.");
        }

        // OAuth2User: 인증이 성공하면 외부 제공자로부터 반환되는 사용자 프로필 정보입니다.
        // 일반 로그인과 OAuth2 로그인을 동일한 방식으로 처리하기 위해, 사용자 정보를 PrincipalDetails 객체에 담아서 반환합니다.
        // 이 반환된 PrincipalDetails 객체는 Spring Security의 Authentication 객체로 사용되며, 사용자 인증 정보를 포함합니다.
        System.out.println("oauth2User.getAttributes() : " + oauth2User.getAttributes());
        return new PrincipalDetails(userEntity, oauth2User.getAttributes());    // 이것이 Authentication 객체 안에 들어간다.
    }
}
