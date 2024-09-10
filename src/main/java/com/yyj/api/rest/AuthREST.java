package com.yyj.api.rest;

import com.yyj.api.dto.LoginDTO;
import com.yyj.api.dto.RegisterDTO;
import com.yyj.api.dto.TokenDTO;
import com.yyj.api.jwt.JwtHelper;
import com.yyj.api.model.RefreshToken;
import com.yyj.api.model.Youser;
import com.yyj.api.repository.RefreshTokenRepository;
import com.yyj.api.repository.YouserRepository;
import com.yyj.api.service.YouserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthREST {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RefreshTokenRepository refreshTokenRepository;

    @Autowired
    YouserRepository youserRepository;

    @Autowired
    JwtHelper jwtHelper;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    YouserService youserService;

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> login(@Valid @RequestBody LoginDTO dto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        Youser youser = (Youser) authentication.getPrincipal();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setOwner(youser);
        refreshTokenRepository.save(refreshToken);

        String accessToken = jwtHelper.generateAccessToken(youser);
        String refreshTokenString = jwtHelper.generateRefreshToken(youser, refreshToken);

        return ResponseEntity.ok(new TokenDTO(youser.getId(), accessToken, refreshTokenString));
    }

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<?> register(@Valid @RequestBody RegisterDTO dto) {
        Youser youser = new Youser(dto.getUsername(), dto.getEmail(), passwordEncoder.encode(dto.getPassword())); /* what is going on here? */
        youserRepository.save(youser);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setOwner(youser);
        refreshTokenRepository.save(refreshToken);

        String accessToken = jwtHelper.generateAccessToken(youser);
        String refreshTokenString = jwtHelper.generateRefreshToken(youser,refreshToken);

        return ResponseEntity.ok(new TokenDTO(youser.getId(), accessToken, refreshTokenString));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody TokenDTO dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString) && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository.deleteByOwner_Id(jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            return ResponseEntity.ok().build();
        }

        throw new BadCredentialsException("invalid token");
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(@RequestBody TokenDTO dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString) && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository.deleteByOwner_Id(jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            return ResponseEntity.ok().build();
        }

        throw new BadCredentialsException("invalid token");
    }

    @PostMapping("/access-token")
    public ResponseEntity<?> accessToken(@RequestBody TokenDTO dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString) && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            Youser youser = youserService.findById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString));
            String accessToken = jwtHelper.generateAccessToken(youser);

            return ResponseEntity.ok(new TokenDTO(youser.getId(), accessToken, refreshTokenString));
        }

        throw new BadCredentialsException("invalid token");
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody TokenDTO dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString) && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository.deleteById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString));
            Youser youser = youserService.findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setOwner(youser);
            refreshTokenRepository.save(refreshToken);
            String accessToken = jwtHelper.generateAccessToken(youser);
            String newRefreshTokenString = jwtHelper.generateRefreshToken(youser, refreshToken);

            return ResponseEntity.ok(new TokenDTO(youser.getId(), accessToken, newRefreshTokenString));
        }

        throw new BadCredentialsException("invalid token");
    }
}
