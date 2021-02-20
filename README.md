### client certificate test

- step 1: 127.0.0.1 123456.dev-server.aaa.com
- step 2: createCertificateAndKeyStore
- step 3: nginx config and start
- step 4: clientCertificationTest


### Configs

- certificates and keystore file: ClientCertificate/tree/master/certificates
- nginx.config: src/main/resources/nginx.conf

---

### Deprecated：Use Private CA for client authentication （Demo） 

#### step 1:Prepare certs and private-key
- Create a Root CA
- Issue a private certificate and download private-key


#### step 2:Save certs and private-key
> certificates/issued
- IssuedCert.pem
- Private.pem
- RootCert.pem

#### step 3:Create keystore file: run createIssuedKeyStore
#### step 4:nginx config (Root CA) and start
```
server {
	client_max_body_size 100M;
    listen       443 ssl;
		
	#server_name 9a2fjk9c79.dev-server.aaa.com

	ssl_certificate "server.pem";
    ssl_certificate_key "server_private_key.key";
    ssl_password_file "server_password.sh";
	
    # self sign certificate
    #ssl_client_certificate "client.crt";
    ssl_client_certificate "RootCert.pem"; <<<<<<<<<<<<<<< Root CA 
	ssl_verify_client on;

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
		
        ...
    }
```
#### step 5:run issuedClientCertificationTest
