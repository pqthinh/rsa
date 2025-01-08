// http_server.cpp
#include "rsa_lib.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <thread>
#include <sstream>
#include <map>
#include <iostream>
#include <iomanip>
#include <vector>

// Function to URL-decode a string
std::string url_decode(const std::string &SRC)
{
    std::string ret;
    char ch;
    int i, ii;
    for (i = 0; i < SRC.length(); i++)
    {
        if (SRC[i] != '%')
        {
            if (SRC[i] == '+')
                ret += ' ';
            else
                ret += SRC[i];
        }
        else
        {
            sscanf(SRC.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i = i + 2;
        }
    }
    return ret;
}

// Function to parse HTTP headers into a map
std::map<std::string, std::string> parse_headers(const std::string &headers)
{
    std::map<std::string, std::string> header_map;
    std::istringstream stream(headers);
    std::string line;
    while (std::getline(stream, line) && line != "\r")
    {
        size_t pos = line.find(':');
        if (pos != std::string::npos)
        {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            // Trim whitespace
            key.erase(key.find_last_not_of(" \n\r\t") + 1);
            value.erase(0, value.find_first_not_of(" \n\r\t"));
            value.erase(value.find_last_not_of(" \n\r\t") + 1);
            header_map[key] = value;
        }
    }
    return header_map;
}

// Function to handle a single client connection
void handle_client(int client_socket)
{
    const int buffer_size = 4096;
    char buffer[buffer_size];
    memset(buffer, 0, buffer_size);

    // Read the request
    ssize_t bytes_received = recv(client_socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0)
    {
        close(client_socket);
        return;
    }

    std::string request(buffer, bytes_received);
    std::istringstream request_stream(request);
    std::string request_line;
    std::getline(request_stream, request_line);

    // Parse the request line
    std::istringstream request_line_stream(request_line);
    std::string method;
    std::string path;
    std::string http_version;
    request_line_stream >> method >> path >> http_version;

    // Parse headers
    std::string headers;
    std::getline(request_stream, headers, '\r');
    std::getline(request_stream, headers, '\n');
    std::string all_headers = "";
    while (headers != "")
    {
        all_headers += headers + "\r\n";
        std::getline(request_stream, headers, '\r');
        std::getline(request_stream, headers, '\n');
    }
    auto header_map = parse_headers(all_headers);

    // Determine content length
    int content_length = 0;
    if (header_map.find("Content-Length") != header_map.end())
    {
        content_length = std::stoi(header_map["Content-Length"]);
    }

    // Read the body
    std::string body;
    if (content_length > 0)
    {
        body.resize(content_length);
        request_stream.read(&body[0], content_length);
    }

    // Prepare the response
    std::string response;

    // Handle different endpoints
    if (path == "/generate_keys" && method == "POST")
    {
        // Expecting JSON: {"keysize": 2048}
        // Simple JSON parsing
        int keysize = 0;
        size_t pos = body.find("\"keysize\"");
        std::clog << "body: " << body << std::endl;
        std::clog << "pos: " << pos << std::endl;
        if (pos != std::string::npos)
        {
            size_t colon = body.find(':', pos);
            size_t comma = body.find(',', colon);
            size_t end = (comma == std::string::npos) ? body.find('}', colon) : comma;
            std::string keysize_str = body.substr(colon + 1, end - colon - 1);
            keysize = std::stoi(keysize_str);
        }

        if (keysize < 512 || keysize % 64 != 0)
        {
            std::string bad_request = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            send(client_socket, bad_request.c_str(), bad_request.length(), 0);
            close(client_socket);
            return;
        }

        try
        {
            PublicKey pub;
            PrivateKey priv;
            CreateRSAKey(keysize, false, false, pub, priv);

            std::string public_key = pub.ToHexa();
            std::string private_key = priv.ToHexa();

            // Create JSON response
            std::string json_response = "{ \"public_key\": \"" + public_key + "\", \"private_key\": \"" + private_key + "\" }";

            // Create HTTP response
            std::ostringstream oss;
            oss << "HTTP/1.1 200 OK\r\n"
                << "Content-Type: application/json\r\n"
                << "Content-Length: " << json_response.length() << "\r\n"
                << "Connection: close\r\n"
                << "\r\n"
                << json_response;

            response = oss.str();
        }
        catch (const std::exception &e)
        {
            std::string internal_error = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            send(client_socket, internal_error.c_str(), internal_error.length(), 0);
            close(client_socket);
            return;
        }
    }
    else if (path == "/encrypt" && method == "POST")
    {
        // Expecting JSON: { "public_key": "...", "plaintext": "..." }
        // Simple JSON parsing
        std::string public_key;
        std::string plaintext;

        size_t pos_pub = body.find("\"public_key\"");
        if (pos_pub != std::string::npos)
        {
            size_t colon = body.find(':', pos_pub);
            size_t quote1 = body.find('\"', colon);
            size_t quote2 = body.find('\"', quote1 + 1);
            public_key = body.substr(quote1 + 1, quote2 - quote1 - 1);
        }

        size_t pos_pt = body.find("\"plaintext\"");
        if (pos_pt != std::string::npos)
        {
            size_t colon = body.find(':', pos_pt);
            size_t quote1 = body.find('\"', colon);
            size_t quote2 = body.find('\"', quote1 + 1);
            plaintext = body.substr(quote1 + 1, quote2 - quote1 - 1);
        }

        if (public_key.empty() || plaintext.empty())
        {
            std::string bad_request = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            send(client_socket, bad_request.c_str(), bad_request.length(), 0);
            close(client_socket);
            return;
        }

        try
        {
            // Parse public key
            size_t dash = public_key.find('-');
            if (dash == std::string::npos)
                throw std::runtime_error("Invalid public key format");

            PublicKey pub;
            pub.nn.set_str(public_key.substr(0, dash), 16);
            pub.ee.set_str(public_key.substr(dash + 1), 16);

            // Convert plaintext to byte vector
            std::vector<unsigned char> plaintext_bytes(plaintext.begin(), plaintext.end());

            // Encrypt
            std::vector<unsigned char> encrypted = pub.Encrypt(plaintext_bytes);

            // Convert encrypted bytes to hex string
            std::ostringstream enc_hex;
            for (auto byte : encrypted)
            {
                enc_hex << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::string encrypted_text = enc_hex.str();

            // Create JSON response
            std::string json_response = "{ \"encrypted_text\": \"" + encrypted_text + "\" }";

            // Create HTTP response
            std::ostringstream oss;
            oss << "HTTP/1.1 200 OK\r\n"
                << "Content-Type: application/json\r\n"
                << "Content-Length: " << json_response.length() << "\r\n"
                << "Connection: close\r\n"
                << "\r\n"
                << json_response;

            response = oss.str();
        }
        catch (const std::exception &e)
        {
            std::string internal_error = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            send(client_socket, internal_error.c_str(), internal_error.length(), 0);
            close(client_socket);
            return;
        }
    }
    else if (path == "/decrypt" && method == "POST")
    {
        // Expecting JSON: { "private_key": "...", "encrypted_text": "..." }
        // Simple JSON parsing
        std::string private_key;
        std::string encrypted_text;

        size_t pos_priv = body.find("\"private_key\"");
        if (pos_priv != std::string::npos)
        {
            size_t colon = body.find(':', pos_priv);
            size_t quote1 = body.find('\"', colon);
            size_t quote2 = body.find('\"', quote1 + 1);
            private_key = body.substr(quote1 + 1, quote2 - quote1 - 1);
        }

        size_t pos_enc = body.find("\"encrypted_text\"");
        if (pos_enc != std::string::npos)
        {
            size_t colon = body.find(':', pos_enc);
            size_t quote1 = body.find('\"', colon);
            size_t quote2 = body.find('\"', quote1 + 1);
            encrypted_text = body.substr(quote1 + 1, quote2 - quote1 - 1);
        }

        if (private_key.empty() || encrypted_text.empty())
        {
            std::string bad_request = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            send(client_socket, bad_request.c_str(), bad_request.length(), 0);
            close(client_socket);
            return;
        }

        try
        {
            // Parse private key
            size_t dash = private_key.find('-');
            if (dash == std::string::npos)
                throw std::runtime_error("Invalid private key format");

            PrivateKey priv;
            priv.nn.set_str(private_key.substr(0, dash), 16);
            priv.dd.set_str(private_key.substr(dash + 1), 16);

            // Convert encrypted hex string to byte vector
            std::vector<unsigned char> encrypted_bytes;
            if (encrypted_text.length() % 2 != 0)
                throw std::runtime_error("Invalid encrypted_text length");

            for (size_t i = 0; i < encrypted_text.length(); i += 2)
            {
                std::string byte_str = encrypted_text.substr(i, 2);
                unsigned char byte = static_cast<unsigned char>(strtol(byte_str.c_str(), nullptr, 16));
                encrypted_bytes.push_back(byte);
            }

            // Decrypt
            std::vector<unsigned char> decrypted = priv.Decrypt(encrypted_bytes);

            // Convert decrypted bytes to string
            std::string decrypted_text(decrypted.begin(), decrypted.end());

            // Create JSON response
            std::string json_response = "{ \"decrypted_text\": \"" + decrypted_text + "\" }";

            // Create HTTP response
            std::ostringstream oss;
            oss << "HTTP/1.1 200 OK\r\n"
                << "Content-Type: application/json\r\n"
                << "Content-Length: " << json_response.length() << "\r\n"
                << "Connection: close\r\n"
                << "\r\n"
                << json_response;

            response = oss.str();
        }
        catch (const std::exception &e)
        {
            std::string internal_error = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            send(client_socket, internal_error.c_str(), internal_error.length(), 0);
            close(client_socket);
            return;
        }
    }
    else
    {
        // Not Found
        std::string not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(client_socket, not_found.c_str(), not_found.length(), 0);
        close(client_socket);
        return;
    }

    // Send the response
    send(client_socket, response.c_str(), response.length(), 0);

    // Close the connection
    close(client_socket);
}

int main()
{
    // Define the port number
    const int PORT = 18080;

    // Create a socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Define the server address
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    address.sin_port = htons(PORT);

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_fd, 10) < 0)
    {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server is listening on port " << PORT << "...\n";

    // Accept and handle incoming connections
    while (true)
    {
        int client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (client_socket < 0)
        {
            perror("accept failed");
            continue;
        }

        // Handle the client in a separate thread
        std::thread(handle_client, client_socket).detach();
    }

    // Close the server socket
    close(server_fd);

    return 0;
}
