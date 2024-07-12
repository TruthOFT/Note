package com.note.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.note.entity.dto.Account;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends IService<Account>, UserDetailsService {

    Account findUserByUsernameOrEmail(String name_or_email);

}
