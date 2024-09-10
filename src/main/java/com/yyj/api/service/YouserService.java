package com.yyj.api.service;

import com.yyj.api.model.Youser;
import com.yyj.api.repository.YouserRepository;
import jakarta.validation.constraints.Email;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class YouserService implements UserDetailsService {
    @Autowired
    YouserRepository youserRepository;

    @Override
    public Youser loadUserByUsername(String email) throws UsernameNotFoundException {
        return youserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("email not found"));
    }

    public Youser findById(String id) {
        return youserRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("user id not found"));
    }
}
