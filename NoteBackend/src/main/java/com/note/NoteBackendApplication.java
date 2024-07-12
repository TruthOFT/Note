package com.note;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.note.mapper")
public class NoteBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(NoteBackendApplication.class, args);
    }

}
