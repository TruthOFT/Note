package com.note.entity.dto;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@TableName("db_user")
public class Account {
    Integer id;
    String username;
    String email;
    String password;
    String role;
    Date registerTime;
}
