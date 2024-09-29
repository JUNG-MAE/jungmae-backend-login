package login.jungmae.login.config.jwt;

public interface JwtProperties {

    String SECRET = "kan";
    int EXPIRATION_TIME = 60000 * 10 * 10;   // 10분 * 10
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
