package com.alessio.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {
	
	@GetMapping({"/", "/hello", ""})
	public String helloWorld() {
		return "Hello World";
	}
	
	@GetMapping({"/h2-console"})
	public String h2() {
		return "Hello World";
	}
}
