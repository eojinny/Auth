package com.chuca.oauth.auth.repository;

import com.chuca.oauth.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    User findByUserId(String userId);
    User findByEmail(String email);
}
