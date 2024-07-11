package com.note.entity;


import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RestBean<T> {

    int code;
    T data;
    String msg;

    public static <T> RestBean<T> success(T data, String msg) {
        return new RestBean<>(200, data, msg);
    }

    public static <T> RestBean<T> failure(int code, T data, String msg) {
        return new RestBean<>(code, data, msg);
    }

    public static <T> RestBean<T> success() {
        return new RestBean<>(200, null, "");
    }

    public static <T> RestBean<T> failure() {
        return new RestBean<>(401, null, "");
    }


    public String asJsonString() {
        return JSON.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
