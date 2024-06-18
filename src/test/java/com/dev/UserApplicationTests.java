package com.dev;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class UserApplicationTests {

	@Test
	void helloTest() {
		String hello = "Hello, World!";
		assert(hello.equals("Hello, World!"));
	}

}
