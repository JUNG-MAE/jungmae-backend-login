package login.jungmae.login.domain.oauth;

import lombok.Data;

@Data
public class NaverTokenBody {
    private String access_token;
    private String refresh_token;
    private String token_type;
    private int expires_in;
}
