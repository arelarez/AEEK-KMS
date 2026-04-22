#include <grpcpp/grpcpp.h>

void RunServer() {
    std::string server_address("0.0.0.0:50051");
    MyServiceImpl service;
    std::string key_contents = LoadFile("server.key");
    std::string cert_contents = LoadFile("server.crt");
    std::string root_cert_contents = LoadFile("ca.crt");

    grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {
        key_contents, cert_contents
    };

    grpc::SslServerCredentialsOptions ssl_opts;
    ssl_opts.pem_key_cert_pairs.push_back(pkcp);
    ssl_opts.pem_root_certs = root_cert_contents;
    ssl_opts.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;

    auto server_creds = grpc::SslServerCredentials(ssl_opts);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(&service);
}