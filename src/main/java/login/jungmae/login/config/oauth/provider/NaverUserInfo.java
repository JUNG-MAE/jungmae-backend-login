package login.jungmae.login.config.oauth.provider;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo{

    private Map<String, Object> attributes; // oauth2User.getAttributes()

    // {id=7vCv6LhWKM7PBznen65Alm2dkd-uFoVCIMtF6xdY2z0,email=dlrghks2090@naver.com,name=김익환}
    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return attributes.get("id").toString() ;
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getEmail() {
        return attributes.get("email").toString();
    }

    @Override
    public String getName() {
        return attributes.get("name").toString();
    }
}
