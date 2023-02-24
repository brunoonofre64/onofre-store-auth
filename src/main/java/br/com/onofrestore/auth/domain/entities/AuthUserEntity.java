package br.com.onofrestore.auth.domain.entities;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
@EqualsAndHashCode(callSuper = true)
public class AuthUserEntity extends User {

    final String fullName;
    final Long userId;

    public AuthUserEntity(UserEntity user) {
        super(user.getUsername(), user.getPassword(), Collections.emptyList());

        this.fullName = user.getFullName();
        this.userId = user.getId();
    }
}
