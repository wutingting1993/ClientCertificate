package com.certification.demo;

import java.io.File;
import java.io.FileInputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.ImmutableList;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SelfX509KeyManager implements X509KeyManager {
	private final ImmutableList<X509KeyManager> keyManagers;

	public SelfX509KeyManager(String keystorePath, String password) throws Exception {
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(new File(keystorePath)), password.toCharArray());
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keystore, password.toCharArray());
		this.keyManagers = ImmutableList.copyOf(Arrays.stream(keyManagerFactory.getKeyManagers()).map(keyManager -> (X509KeyManager)keyManager).collect(Collectors.toList()));
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		String[] clientAlias = keyManagers.stream()
			.map(keyManager -> keyManager.getClientAliases(keyType, issuers))
			.flatMap(Arrays::stream)
			.toArray(String[]::new);
		log.info("getClientAliases:" + StringUtils.join(clientAlias));
		return clientAlias;
	}

	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		String clientAlias = keyManagers.stream()
			.map(keyManager -> keyManager.chooseClientAlias(keyType, issuers, socket))
			.filter(StringUtils::isNotBlank)
			.findFirst()
			.orElse(null);
		log.info("chooseClientAlias:" + clientAlias);
		return clientAlias;
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {

		String[] serverAliases = keyManagers.stream()
			.map(keyManager -> keyManager.getServerAliases(keyType, issuers))
			.flatMap(Arrays::stream)
			.toArray(String[]::new);
		log.info("getServerAliases:" + StringUtils.join(serverAliases));
		return serverAliases;
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		String serverAliases = keyManagers.stream()
			.map(keyManager -> keyManager.chooseServerAlias(keyType, issuers, socket))
			.filter(StringUtils::isNotBlank)
			.findFirst()
			.orElse(null);
		log.info("chooseServerAlias:" + StringUtils.join(serverAliases));
		return serverAliases;
	}

	public X509Certificate[] getCertificateChain(String alias) {
		X509Certificate[] certificates = keyManagers.stream()
			.map(keyManager -> keyManager.getCertificateChain(alias))
			.filter(ArrayUtils::isNotEmpty)
			.findFirst()
			.orElse(null);
		log.info("find certificates: " + Objects.nonNull(certificates));
		return certificates;
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		PrivateKey privateKey = keyManagers.stream()
			.map(keyManager -> keyManager.getPrivateKey(alias))
			.filter(Objects::nonNull)
			.findFirst()
			.orElse(null);
		log.info("find privateKey: " + Objects.nonNull(privateKey));
		return privateKey;
	}
}
