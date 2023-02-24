package br.com.onofrestore.auth.core.service;

import br.com.onofrestore.auth.domain.entities.AuthUserEntity;
import br.com.onofrestore.auth.domain.entities.UserEntity;
import br.com.onofrestore.auth.domain.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Email do login nao encontrado."));

        return new AuthUserEntity(userEntity);
    }
}
