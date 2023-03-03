package br.com.onofrestore.auth.domain.entities;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
@EqualsAndHashCode(callSuper = true)
public class AuthUserEntity extends User {

    final String fullName;
    final Long userId;
    final String userUuid;
    final String userCpf;

    public AuthUserEntity(UserEntity user, Collection<? extends GrantedAuthority> authorities) {
        super(user.getUsername(), user.getPassword(), authorities);

        this.fullName = user.getFullName();
        this.userId = user.getId();
        this.userUuid = user.getUuid();
        this.userCpf = user.getCpf();
    }
}
