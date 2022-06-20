package cz.fit.bp.fw_author;

import org.apache.tomcat.util.buf.HexUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

@SpringBootApplication(scanBasePackages = "cz.fit.bp.fw_author.*")
public class FwAuthorApplication {

    public static void main(String[] args) {

        SpringApplication.run(FwAuthorApplication.class, args);
    }

}
