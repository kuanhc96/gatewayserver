package com.example.gatewayserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import redis.clients.jedis.RedisClient;

@Configuration
public class RedisConfig {
	@Value("${redis.location}")
	private String redisLocation;

	@Bean(destroyMethod = "close")
	public RedisClient redisClient() {
		return RedisClient.create(redisLocation);
	}
}
