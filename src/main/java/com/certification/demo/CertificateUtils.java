package com.certification.demo;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

import com.certification.demo.dto.ClientCertificateDto;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertificateUtils {

	public static ClientCertificateDto generateCertificate(String dn, int days, String algorithm) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		LocalDateTime now = LocalDateTime.now();

		X509CertInfo info = new X509CertInfo();
		X500Name owner = new X500Name(dn);

		info.set(X509CertInfo.VALIDITY, new CertificateValidity(Timestamp.valueOf(now), Timestamp.valueOf(now.plusDays(days))));
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
		info.set(X509CertInfo.SUBJECT, owner);
		info.set(X509CertInfo.ISSUER, owner);
		info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		AlgorithmId algorithmId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmId));

		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(keyPair.getPrivate(), algorithm);

		// Update the algorithm, and resign.
		algorithmId = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithmId);
		cert = new X509CertImpl(info);
		cert.sign(keyPair.getPrivate(), algorithm);

		return ClientCertificateDto.builder()
			.privateKey(certificationToPemString(new JcaPKCS8Generator(keyPair.getPrivate(), null).generate()))
			.certification(certificationToPemString(cert))
			.build();
	}

	public static KeyStore createKeyStore(ClientCertificateDto clientCertificate, String password) {

		try {
			KeyStore keystore = KeyStore.getInstance("PKCS12");
			keystore.load(null, password.toCharArray());
			X509Certificate certificate = readCertificate(clientCertificate.getCertification());
			X500Principal principal = certificate.getSubjectX500Principal();
			LdapName ldapDN = new LdapName(principal.getName());
			PrivateKey privateKey = readPrivateKey(clientCertificate.getPrivateKey());
			KeyStore.PrivateKeyEntry keyEntry = new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] {certificate});
			KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password.toCharArray());
			keystore.setEntry(getAlias(ldapDN.getRdns()), keyEntry, protection);
			return keystore;
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}

	private static String getAlias(List<Rdn> rdns) {
		return (String)rdns.stream().filter(rdn -> "CN".equals(rdn.getType())).findFirst().map(Rdn::getValue).orElse(null);
	}

	private static String certificationToPemString(Object keyPair) throws IOException {
		StringWriter sw1 = new StringWriter();
		try (JcaPEMWriter pw = new JcaPEMWriter(sw1)) {
			pw.writeObject(keyPair);
		}
		return sw1.toString();
	}

	public static X509Certificate readCertificate(String certificate) throws Exception {
		try (StringReader reader = new StringReader(certificate)) {
			PEMParser pemParser = new PEMParser(reader);
			return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder)pemParser.readObject());
		}
	}

	public static RSAPrivateKey readPrivateKey(String privateKey) throws Exception {
		try (StringReader reader = new StringReader(privateKey)) {
			PEMParser pemParser = new PEMParser(reader);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			Object object = pemParser.readObject();
			PrivateKeyInfo privateKeyInfo;
			if (object instanceof PEMKeyPair) {
				privateKeyInfo = ((PEMKeyPair)object).getPrivateKeyInfo();
			} else {
				privateKeyInfo = PrivateKeyInfo.getInstance(object);
			}
			return (RSAPrivateKey)converter.getPrivateKey(privateKeyInfo);
		}
	}
}
