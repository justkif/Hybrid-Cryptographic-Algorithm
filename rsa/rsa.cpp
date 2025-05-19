#include <openssl/rsa.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>

std::vector<unsigned char> rsa_encrypt(RSA* rsa, const std::vector<unsigned char>& plaintext) {
    std::vector<unsigned char> ciphertext(RSA_size(rsa));
    int len = RSA_public_encrypt((int)plaintext.size(), plaintext.data(), ciphertext.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        std::cerr << "Error during encryption" << std::endl;
        exit(1);
    }
    ciphertext.resize(len);
    return ciphertext;
}

std::vector<unsigned char> rsa_decrypt(RSA* rsa, const std::vector<unsigned char>& ciphertext) {
    std::vector<unsigned char> plaintext(RSA_size(rsa));
    int len = RSA_private_decrypt((int)ciphertext.size(), ciphertext.data(), plaintext.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        std::cerr << "Error during decryption" << std::endl;
        exit(1);
    }
    plaintext.resize(len);
    return plaintext;
}

int main() {
    auto start_time = std::chrono::high_resolution_clock::now();

    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);

    if (RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) {
        std::cerr << "Error generating RSA key pair" << std::endl;
        exit(1);
    }

    std::string plaintext_str = "This is a message.";
    std::vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());

    std::vector<unsigned char> encrypted_data = rsa_encrypt(rsa, plaintext);
    std::cout << "Encrypted data: ";
    for (size_t i = 0; i < encrypted_data.size(); ++i) {
        printf("%02x", encrypted_data[i]);
    }
    std::cout << std::endl << std::endl;

    std::vector<unsigned char> decrypted_data = rsa_decrypt(rsa, encrypted_data);
    std::string decrypted_str(decrypted_data.begin(), decrypted_data.end());
    std::cout << "Decrypted data: " << decrypted_str << std::endl << std::endl;

    BN_free(bn);
    RSA_free(rsa);

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_duration = end_time - start_time;
    std::cout << "Total execution time: " << total_duration.count() << " seconds.";

    return 0;
}