### client certificate test

- step 1: 127.0.0.1 123456.dev-server.aaa.com
- step 2: createCertificateAndKeyStore
- step 3: nginx config and start
- step 4: clientCertificationTest


### Configs

- certificates and keystore file: https://github.com/wutingting1993/ClientCertificate/tree/master/certificates
- nginx.config: https://github.com/wutingting1993/ClientCertificate/blob/master/src/main/resources/nginx.conf

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

# 图解SSL/TLS认证流程
https://blog.csdn.net/u012175637/article/details/84138925

红色部分为服务器端消息，紫色部分为客户端消息，黑色部分为双向认证需要的消息，绿色部分为某些情况下的特殊需求，这里不做详细的解释。

下图内容都可以通过wireshare 抓包看到具体的内容，有什么不清楚的可以通过wireshare 抓包自己看一下就会一目了然了。

简单来说SSL握手的目的就是为了获得客户端和服务器进行通信时使用的秘钥，根据不同的需求选择单向认证或者双向认证

![image](https://user-images.githubusercontent.com/12660487/108589170-1b967300-7398-11eb-8db3-524d43486d4e.png)


