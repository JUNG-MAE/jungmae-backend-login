package login.jungmae.login.domain.oauth;

import lombok.Data;

@Data
public class NaverProfile {

    private String resultcode;
    private String message;
    private Response response;


    @Data
    public static class Response {
        public String id;
        public String email;
        public String name;
    }

}
