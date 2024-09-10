package com.yyj.api.repository;

import com.yyj.api.model.Youser;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface YouserRepository extends MongoRepository<Youser, String> {
    Optional<Youser> findByEmailAndPassword(String email, String password);
    Optional<Youser> findByEmail(String email);
}
