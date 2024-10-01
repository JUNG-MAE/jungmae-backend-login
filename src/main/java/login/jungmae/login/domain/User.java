package login.jungmae.login.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // auto increment
    private long id;
    private String username;
    private String name;
    private String password;
    private String email;
    private String role;

    private String provider;

    @CreationTimestamp
    private Timestamp createDate;

    @Builder
    public User(String username,String name, String password, String email, String role, String provider, Timestamp createDate) {
        this.username = username;
        this.name = name;
        this.password = password;
        this.email = email;
        this.role = role;
        this.provider = provider;
        this.createDate = createDate;
    }

    public List<String> getRoleList(){
        if (this.role.length() > 0) {
            return Arrays.asList(this.role.split(","));
        }
        else {
            return new ArrayList<>();
        }
    }

}
