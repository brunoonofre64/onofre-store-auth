package br.com.onofrestore.auth.core.service;

import br.com.onofrestore.auth.domain.entities.AuthUserEntity;
import br.com.onofrestore.auth.domain.entities.UserEntity;
import br.com.onofrestore.auth.domain.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JpaUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Email do login nao encontrado."));

        return new AuthUserEntity(userEntity, getAuthorities(userEntity));
    }

    private Collection<GrantedAuthority> getAuthorities(UserEntity user) {
        return user
                .getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getProfile()))
                .collect(Collectors.toSet());
    }
}
