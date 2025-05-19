HYBRID CRYPTOGRAPHIC ALGORITHM COMBINING SYMMETRIC ENCRYPTION WITH QUANTUM-RESISTANT METHODS
============================================================================================

The increasing potential of quantum computing poses a significant threat to current cryptographic systems, particularly those relying on widely used asymmetric encryption algorithms like `RSA` or `ECC`. As quantum computers evolve, they could break these encryption methods using `Shor's algorithm`, which can factor large numbers efficiently. In response to this, the field of post-quantum cryptography has been working to develop new cryptographic techniques that are resistant to quantum attacks. One promising area is lattice-based cryptography, which offers quantum resistance. This project proposes a hybrid cryptographic algorithm combining the efficiency of symmetric encryption with the quantum-resistant nature of lattice cryptography. The proposed system uses `AES` for fast encryption and decryption in combination with `ML-KEM-512` for key exchange, ensuring quantum-resistant secure communication. 

Table of Contents
=================

- [Problem Analysis](#problem-analysis)
- [Solution Design](#solution-design)
- [Implementation](#implementation)
    - [Setup](#setup)
    - [Execute Main Code](#execute-main-code)
    - [Execute RSA Code](#execute-rsa-code)
- [Evaluation](#evaluation)
- [Acknowledgements](#acknowledgements)

Problem Analysis
================

Asymmetric encryption offers the advantage of secure key exchange and digital signatures without the need for a pre-shared secret, making it ideal for public communication where confidentiality must be preserved. However, it is computationally expensive, with significant overhead in key generation, encryption, and decryption processes. While widely used algorithms like `RSA` or `ECC` are popular, they are vulnerable to potential quantum computing attacks, especially through `Shor’s algorithm`.

Symmetric encryption, such as `AES`, is a highly efficient and fast method, making it ideal for bulk data encryption due to its low computational overhead. However, its main disadvantage lies in the secure exchange of the secret key. If the key is intercepted during transmission, the security of the encrypted data is compromised, exposing it to potential threats.

While symmetric encryption methods like `AES` remain secure in the face of quantum computing (with `Grover’s algorithm` providing only a quadratic speedup), the vulnerability of asymmetric encryption algorithms to quantum attacks calls for the use of quantum-resistant alternatives.

Reference: [Advanced Encryption Techniques for Securing Data Transfer in Cloud Computing: A Comparative Analysis of Classical and Quantum-Resistant Methods](https://www.researchgate.net/profile/Pankaj-Gupta-76/publication/386141287_Advanced_Encryption_Techniques_for_Securing_Data_Transfer_in_Cloud_Computing_A_Comparative_Analysis_of_Classical_and_Quantum-Resistant_Methods/links/67464d3b790d154bf9adaaef/Advanced-Encryption-Techniques-for-Securing-Data-Transfer-in-Cloud-Computing-A-Comparative-Analysis-of-Classical-and-Quantum-Resistant-Methods.pdf).

Solution Design
===============

![System Architecture](/public/System%20Architecture.png)

The project proposes a hybrid approach that aims to combine the strengths of both asymmetric and symmetric encryption. Asymmetric encryption can be used for secure key exchange, while symmetric encryption can be employed for fast and efficient data encryption. This combination ensures both secure key management and efficient encryption of large datasets.  
 
Asymmetric encryption will use Lattice-based cryptography `ML-KEM-512`, as it is resistant to quantum algorithms for secure key exchange. `AES (Advanced Encryption Standard)` will be used for symmetric encryption, providing fast encryption and decryption for data confidentiality. 
 
Initially, the two parties perform key exchange using `ML-KEM-512` algorithm to securely establish a symmetric key, with the algorithm being resistant to quantum attacks. Once the symmetric key is exchanged, `AES` encryption is employed for data confidentiality, offering both speed and robustness in encryption/decryption. This hybrid system effectively secures key exchange and data encryption against quantum computing threats while maintaining high performance, ensuring secure end-to-end communication. 
 
`ML-KEM-512` leverages the mathematical structure of high-dimensional lattices to secure communications. These cryptographic systems are considered resistant to quantum attacks because the hardest problems in lattice-based cryptography, such as finding short vectors or solving the learning with errors (LWE) problem, cannot be efficiently solved by known quantum algorithms. This makes lattice-based schemes a promising candidate for post-quantum cryptography, ensuring security even in the face of potential future quantum computing advancements.  
 
`AES` is a widely used symmetric block cipher that operates on fixed-size 128-bit data blocks, supporting key sizes of 128, 192, and 256 bits. The security of `AES` relies on the computational difficulty of brute-forcing the key through exhaustive search, which remains infeasible for appropriately sized keys. Even in a post-quantum world, `AES` remains secure because `Grover's algorithm` can only offer a quadratic speedup in searching the key space, meaning that for a 256-bit key, quantum computers would still require an enormous number of resources to break the encryption, making it highly resistant to quantum threats.

Implementation
==============

## Setup

This section is optional. If you prefer not to manually install the libraries, you can skip ahead to [Execute Main Code](#execute-main-code). However, a C++ compiler is still required. You can use `cl` by installing [Visual Studio 2022](#1-visual-studio-2022), excluding **C++ CMake tools for Windows** and **Windows 10 SDK**, and setting up the environment as described in [Set Up Windows Environment for `cl.exe`](#6-set-up-windows-environment-for-clexe). Alternatively, `g++` or `clang++` will work just fine.

### 1. Visual Studio 2022
Visual Studio 2022 will be used to compile the code and to build libraries.

1. Download Visual Studio 2022 from the official site: [Visual Studio Download](https://visualstudio.microsoft.com/).
2. During installation, select **Desktop development with C++** with the following components:
   - **MSVC v143 - VS 2022 C++ x64/86 build tools** (or the latest available version).
   - **C++ CMake tools for Windows**.
   - **Windows 10 SDK** (or the latest available version).
3. Finish the installation by following the on-screen instructions.

### 2. Perl and NASM
OpenSSL library requires Perl and NASM for building from source.

1. **Install Perl**
   - Download Strawberry Perl from: [Strawberry Perl](https://strawberryperl.com/).
   - Install Strawberry Perl by following the provided instructions.
   - Add Strawberry Perl to the System Path:
      - Open **System Properties** > **Environment Variables**.
      - In **System variables**, select **Path** and click **Edit**.
      - Click **New** and add:
      ```
      C:\Strawberry\perl\bin
      C:\Strawberry\c\bin
      ```
      - Verify Perl installation by opening a new command prompt and run:
      ```
      perl -v
      ```
2. **Install NASM**:
   - Download NASM from: [NASM Download](https://www.nasm.us/).
   - Install NASM and add it to the system **Path**.
   - Verify NASM installation by running:
     ```
     nasm -v
     ```

### 3. OpenSSL Library
OpenSSL library will be used in the project, compiled using the Visual Studio 2022 environment.

1. Download OpenSSL from: [OpenSSL Source](https://www.openssl.org/source/).
2. Open the **x64 Native Tools Command Prompt for VS 2022**.
3. **Navigate to the extracted OpenSSL directory** and run the following commands:
   ```
   perl Configure VC-WIN64A --prefix=<path_to_where_you_want_OpenSSL_to_be_installed\a_name_for_OpenSSL_folder>
   nmake
   nmake install
   ```
4. Verify the installation by open a command prompt and type:
   ```
   openssl version
   ```

### 4. OQS Library
OQS library will be used in the project, compiled using the Visual Studio 2022 environment.

1. Download OQS from: [OQS Source](https://github.com/open-quantum-safe/liboqs).
2. Open the **x64 Native Tools Command Prompt for VS 2022**.
3. **Navigate to the extracted OQS directory** and run the following commands:
   ```
   mkdir build
   cd build
   cmake ..
   cmake --build .
   ```

### 5. Reorganize Files

1. Copy the `oqs` folder from `<OQS_library_directory_path\build\include>` to `<OpenSSL_library_directory_path\include>`.
2. Copy all file from `<OQS_library_directory_path\build\lib>` to `<OpenSSL_library_directory_path\lib>`.

### 6. Set Up Windows Environment for `cl.exe`

1. Locate `cl.exe`:
   - Typically found in `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\<version>\bin\Hostx64\x64`.
2. Add `cl.exe` to the System Path:
   - Open **System Properties** > **Environment Variables**.
   - In **System variables**, select **Path** and click **Edit**.
   - Click **New** and add the path to `cl.exe` (exclude cl.exe).
3. Verify the setup by open a new command prompt and run:
   ```
   cl
   ```

## Execute Main Code

The main code is in [Main Code](https://github.com/justkif/Hybrid-Cryptographic-Algorithm/blob/main/main/code.cpp).

1. Open the **x64 Native Tools Command Prompt for VS 2022**.
2. **Navigate to the extracted directory of this repository** and run the following commands:
   ```
   cd main
   cl /I ..\libs\include /EHsc .\code.cpp libssl.lib libcrypto.lib ws2_32.lib crypt32.lib user32.lib oqs.lib /link /LIBPATH:..\libs\lib Advapi32.lib
   .\code
   ```

## Execute RSA Code

1. Open the **x64 Native Tools Command Prompt for VS 2022**.
2. **Navigate to the extracted directory of this repository** and run the following commands:
   ```
   cd rsa
   cl .\rsa.cpp /I ..\libs\include /link /LIBPATH:..\libs\lib libssl.lib libcrypto.lib
   .\rsa
   ```

## Evaluation

## Acknowledgements

I would like to express my sincere thanks to **Lê Hồng Vũ** and **Lý Gia Bình** for their dedicated work on the [Problem Analysis](#problem-analysis) and [Solution Design](#solution-design) of the project.

We are also deeply grateful to **Dr. Nguyễn Ngọc Tự** for equipping us with essential knowledge in the field, providing the foundational framework for the project, and offering insightful recommendations to refine and further develop our work.