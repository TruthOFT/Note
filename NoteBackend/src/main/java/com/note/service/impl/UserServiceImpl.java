package com.note.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.note.entity.dto.Account;
import com.note.mapper.UserMapper;
import com.note.service.UserService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, Account> implements UserService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = findUserByUsernameOrEmail(username);
        return User.withUsername(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    @Override
    public Account findUserByUsernameOrEmail(String name_or_email) {
        return this.query().eq("username", name_or_email)
                .or().eq("email", name_or_email)
                .one();
    }
}
