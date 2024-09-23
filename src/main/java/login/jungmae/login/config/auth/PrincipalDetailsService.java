package login.jungmae.login.config.auth;

import login.jungmae.login.model.User;
import login.jungmae.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 로그인 요청이 들어오면 스프링 시큐리티는 /login URL을 통해 인증을 처리하고, 이 과정에서 loadUserByUsername() 메서드가 호출됩니다.
    // PrincipalDetailsService 이 호출되면 loadUserByUsername 메서드가 자동으로 실행됩니다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 loadUserByUsername() 실행");
        // username으로 데이터베이스에서 사용자를 조회합니다. 조회된 사용자 정보를 UserDetails 객체로 변환하여 반환합니다.
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity :   " + userEntity);
        // 조회된 User 객체는 PrincipalDetails 객체로 변환되어 반환됩니다.
        // PrincipalDetails는 스프링 시큐리티에서 요구하는 UserDetails 인터페이스를 구현한 사용자 정보 객체입니다.
        return new PrincipalDetails(userEntity);

        // 반환된 PrincipalDetails 객체는 스프링 시큐리티의 인증 컨텍스트에 저장되며, 인증된 사용자로서 여러 보안 관련 기능에서 사용됩니다.
        // 이 객체에는 사용자 정보 및 권한 정보가 담겨있습니다.
    }
}
