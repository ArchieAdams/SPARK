cd ./certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -keyout server.key -out server.crt -subj "/CN=authbox.local" -addext "subjectAltName=DNS:authbox.local"
openssl x509 -in /home/archiea/CLionProjects/Authenticator/certs/server.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64