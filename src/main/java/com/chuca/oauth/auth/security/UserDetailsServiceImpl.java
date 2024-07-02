package com.chuca.oauth.auth.security;

import com.chuca.oauth.auth.entity.User;
import com.chuca.oauth.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String user_id) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUserId(user_id);
        String EncodedPassword = userEntity.getPassword();
        if (userEntity == null)
            throw new UsernameNotFoundException( "Not Found id : " + user_id);

        return new UserDetailsImpl(userEntity);
    }

}
