package me.chandlersong.jwt;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Date;


@Log4j2
public class DateTest{

    @Test
    public void printDate(){
        log.info("ok");
    }

    public static void main(String[] args) {

        log.info(new Date(1973773952));
    }
}
