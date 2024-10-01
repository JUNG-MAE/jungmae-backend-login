package login.jungmae.login.domain.dto;

import login.jungmae.login.domain.User;
import lombok.Builder;
import lombok.Data;

import java.sql.Timestamp;

@Data
public class UserDto {
    private String username;
    private String name;
    private String password;
    private String email;
    private String role;

    private String provider;

    private Timestamp createDate;


    public UserDto(User user) {
        this.username = user.getUsername();
        this.name = user.getName();
        this.password = user.getPassword();
        this.email = user.getEmail();
        this.role = user.getRole();
        this.provider = user.getProvider();
        this.createDate = user.getCreateDate();
    }
}
