package com.certification.demo;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.MediaType.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

import com.certification.demo.dto.ClientCertificateDto;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.TcpClient;

/**
 * step 1: 127.0.0.1 123456.dev-server.aaa.com
 * step 2: createCertificateAndKeyStore
 * step 3: nginx config and start
 * step 4: clientCertificationTest
 */
public class ClientCertificationTest {
	private static final String PASSWORD = "test123";

	@Test
	void createCertificateAndKeyStore() throws Exception {
		String distinguishedName = "CN=123456.dev-server.aaa.com,OU=XXX,O=XXX,L=CD,ST=SC,C=CN";
		ClientCertificateDto clientCertificateDto = CertificateUtils.generateCertificate(distinguishedName, 365, "SHA256withRSA");

		String path = Thread.currentThread().getContextClassLoader().getResource(".").getPath();
		String prefix = path.substring(0, path.indexOf("target")) + "certificates/client/";

		FileUtils.writeStringToFile(new File(prefix + "private.key"), clientCertificateDto.getPrivateKey(), StandardCharsets.UTF_8);
		FileUtils.writeStringToFile(new File(prefix + "client.crt"), clientCertificateDto.getCertification(), StandardCharsets.UTF_8);

		KeyStore keystore = CertificateUtils.createKeyStore(clientCertificateDto, PASSWORD);
		try (OutputStream out = new FileOutputStream(new File(prefix + "keystore.p12"))) {
			keystore.store(out, PASSWORD.toCharArray());
		}
	}

	@Test
	void createIssuedKeyStore() throws Exception {
		String path = Thread.currentThread().getContextClassLoader().getResource(".").getPath();
		String prefix = path.substring(0, path.indexOf("target")) + "certificates/issued/";

		ClientCertificateDto clientCertificateDto = ClientCertificateDto.builder()
			.certification(FileUtils.readFileToString(new File(prefix + "IssuedCert.pem"), StandardCharsets.UTF_8))
			.privateKey(FileUtils.readFileToString(new File(prefix + "Private.pem"), StandardCharsets.UTF_8))
			.build();

		KeyStore keystore = CertificateUtils.createKeyStore(clientCertificateDto, PASSWORD);
		try (OutputStream out = new FileOutputStream(new File(prefix + "Keystore.p12"))) {
			keystore.store(out, PASSWORD.toCharArray());
		}
	}

	@Test
	void clientCertificationTest() throws Exception {
		String path = Thread.currentThread().getContextClassLoader().getResource(".").getPath();
		String keystorePath = path.substring(0, path.indexOf("target")) + "certificates/keystore.p12";
		clientCertificationTest(keystorePath);
	}

	private void clientCertificationTest(String keystorePath) throws Exception {
		String url = "https://123456.dev-server.aaa.com/server/v1/auth/actions";
		String body = getWebClient(keystorePath)
			.get()
			.uri(url)
			.header(CONTENT_TYPE, APPLICATION_JSON_VALUE)
			.header(ACCEPT, "*")
			.retrieve().bodyToMono(String.class)
			.block();
		System.out.println(body);
	}

	@Test
	void issuedClientCertificationTest() throws Exception {

		String path = Thread.currentThread().getContextClassLoader().getResource(".").getPath();
		String keystorePath = path.substring(0, path.indexOf("target")) + "certificates//Keystore.p12";
		clientCertificationTest(keystorePath);
	}

	private static WebClient getWebClient(String keystorePath) throws Exception {

		SslContext sslContext = SslContextBuilder.forClient()
			.keyManager(new SelfX509KeyManager(keystorePath, PASSWORD))
			.trustManager(InsecureTrustManagerFactory.INSTANCE)
			.build();

		return WebClient.builder()
			.clientConnector(new ReactorClientHttpConnector(HttpClient
				.from(TcpClient.newConnection())
				.tcpConfiguration(tcpClient -> tcpClient.secure(sslContextSpec -> sslContextSpec.sslContext(sslContext)))
			))
			.build();
	}

}
