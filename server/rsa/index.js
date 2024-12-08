// Hàm tính Ước chung lớn nhất (GCD) của a và b
function gcd(a, b) {
    while (b !== 0) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Hàm tính nghịch đảo modular của a mod m (Dùng thuật toán Euclid mở rộng)
function modInverse(a, m) {
    let m0 = m, y = 0, x = 1;
    
    if (m === 1) return 0;
    
    while (a > 1) {
        let q = Math.floor(a / m);
        let t = m;
        
        m = a % m;
        a = t;
        
        t = y;
        y = x - q * y;
        x = t;
    }
    
    if (x < 0) x += m0;
    
    return x;
}

// Kiểm tra xem một số có phải là số nguyên tố không
function isPrime(num) {
    if (num <= 1) return false;
    for (let i = 2; i <= Math.sqrt(num); i++) {
        if (num % i === 0) return false;
    }
    return true;
}

// Sinh một số nguyên tố ngẫu nhiên trong phạm vi [min, max]
function getRandomPrime(min, max) {
    let prime;
    do {
        prime = Math.floor(Math.random() * (max - min + 1)) + min;
    } while (!isPrime(prime));
    return prime;
}

// Hàm sinh cặp khóa RSA (public, private)
function generateKeys(bits) {
    let p = getRandomPrime(2 ** (bits / 2), 2 ** (bits / 2 + 1));
    let q = getRandomPrime(2 ** (bits / 2), 2 ** (bits / 2 + 1));
    
    const n = p * q; // Tính n = p * q
    const phi = (p - 1) * (q - 1); // Tính phi(n) = (p-1)(q-1)

    let e = 65537;  // Một giá trị e phổ biến (vì e phải là số lẻ, nhỏ và coprime với phi(n))
    while (gcd(e, phi) !== 1) {
        e += 2;
    }

    const d = modInverse(e, phi); // Tính d sao cho d * e ≡ 1 (mod φ(n))

    return {
        publicKey: { e, n },
        privateKey: { d, n }
    };
}

// Ví dụ sử dụng RSA
(async () => {
    const bits = 512;  // Chọn độ dài khóa (512, 1024, 2048 bits, ...). Khóa lớn sẽ an toàn hơn nhưng chậm hơn
    console.log(`Generating RSA keys with ${bits} bits...`);
    
    const { publicKey, privateKey } = generateKeys(bits);
    console.log('RSA keys generated successfully.');

    const message = 'Hello, RSA encryption and decryption!';
    console.log('Original message:', message);

    // Mã hóa thông điệp
    const encryptedMessage = encrypt(publicKey, message);
    console.log('Encrypted message:', encryptedMessage);

    // Giải mã thông điệp
    const decryptedMessage = decrypt(privateKey, encryptedMessage);
    console.log('Decrypted message:', decryptedMessage);
})();
