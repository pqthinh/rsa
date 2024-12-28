### mã hoá rsa với khoá k lớn

### Cài đặt môi trường cpp
brew install gcc

brew install gmp

-- verify library lgmp: 
ls /opt/homebrew/opt/gmp/include/gmpxx.h
ls /opt/homebrew/opt/gmp/lib/libgmpxx.a

-- export path:
export CPLUS_INCLUDE_PATH="/opt/homebrew/opt/gmp/include:$CPLUS_INCLUDE_PATH"
export LIBRARY_PATH="/opt/homebrew/opt/gmp/lib:$LIBRARY_PATH"

-- refresh terminal:
source ~/.zshrc

### Thực thi code:
g++ test_k8192.cpp rsa_lib.cpp -lgmp -lgmpxx -o 8192

g++ -o rsa8192 main.cpp rsa_lib.cpp -I/opt/homebrew/include -L/opt/homebrew/lib -lgmp -lgmpxx -std=c++17

g++ -o rsa main.cpp rsa_lib.cpp -I/opt/homebrew/include -L/opt/homebrew/lib -lgmp -lgmpxx -std=c++17 -pthread
