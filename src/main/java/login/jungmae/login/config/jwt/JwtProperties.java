package login.jungmae.login.config.jwt;

public interface JwtProperties {

    String SECRET = "01234567890123456789012345678901234567890123456789";
    int ACCESS_TOKEN_EXPIRATION_TIME = 1000 * 60 * 60;   // 5분
    int REFRESH_TOKEN_EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 7;    // 7일

    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
