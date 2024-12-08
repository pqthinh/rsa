import { Buffer } from 'buffer';

// Hàm tính Ước chung lớn nhất (GCD) của a và b (Sử dụng Euclidean Algorithm)
function gcd(a, b) {
    while (b !== 0) {
        a %= b;
        [a, b] = [b, a]; // Swap values
    }
    return a;
}

// Hàm tính nghịch đảo modular của a mod m (Dùng Extended Euclidean Algorithm)
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

// Hàm kiểm tra số nguyên tố với tối ưu hoá
function isPrime(num) {
    if (num <= 1) return false;
    if (num === 2) return true;  // Handle the case for 2 separately
    if (num % 2 === 0) return false; // Exclude even numbers
    
    const limit = Math.sqrt(num);
    for (let i = 3; i <= limit; i += 2) {
        if (num % i === 0) return false;
    }
    return true;
}

// Hàm sinh số nguyên tố ngẫu nhiên trong phạm vi [min, max]
function getRandomPrime(min, max) {
    let prime;
    do {
        // Random odd number to increase speed (even numbers cannot be prime except 2)
        prime = Math.floor(Math.random() * (max - min + 1)) + min;
        if (prime % 2 === 0) prime++; // Make sure it's odd
    } while (!isPrime(prime));
    return prime;
}

// Hàm sinh cặp khóa RSA (public, private)
export function generateKeys(bits) {
    // Generate two distinct large primes p and q
    let p = getRandomPrime(2 ** (bits / 2), 2 ** (bits / 2 + 1));
    let q;
    do {
        q = getRandomPrime(2 ** (bits / 2), 2 ** (bits / 2 + 1));
    } while (q === p); // Ensure p and q are distinct

    const n = p * q;
    const phi = (p - 1) * (q - 1);

    let e = 65537;  // A common choice for e
    while (gcd(e, phi) !== 1) {
        e += 2;  // Try the next odd number
    }

    const d = modInverse(e, phi);

    return {
        publicKey: { e, n },
        privateKey: { d, n }
    };
}

// Hàm mã hóa một thông điệp m với khóa công khai (e, n)
export function encrypt(publicKey, message) {
    const { e, n } = publicKey;
    const messageInt = BigInt('0x' + Buffer.from(message, 'utf8').toString('hex'));  // Chuyển chuỗi thành số nguyên

    // Mã hóa m^e mod n
    const encrypted = messageInt ** BigInt(e) % BigInt(n);
    return encrypted.toString();
}

// Hàm giải mã một thông điệp đã mã hóa với khóa riêng (d, n)
export function decrypt(privateKey, encryptedMessage) {
    const { d, n } = privateKey;
    const encryptedInt = BigInt(encryptedMessage);

    // Giải mã c^d mod n
    const decrypted = encryptedInt ** BigInt(d) % BigInt(n);
    const decryptedHex = decrypted.toString(16);  // Chuyển số nguyên giải mã ra dạng hex
    const decryptedMessage = Buffer.from(decryptedHex, 'hex').toString('utf8');  // Chuyển hex thành chuỗi

    return decryptedMessage;
}

// Function to encode an integer into ASN.1 DER format
function toAsn1Integer(value) {
    const hex = value.toString(16); // Convert BigInt to hexadecimal string
    let buffer = Buffer.from(hex, 'hex');
    if (buffer[0] >= 0x80) { // Check if the first byte indicates a negative number
        const newBuffer = Buffer.alloc(buffer.length + 1);
        newBuffer[0] = 0;
        buffer.copy(newBuffer, 1);
        buffer = newBuffer;
    }
    return buffer;
}

// Function to create an RSA public key PEM from e, n
export function createPublicKeyPem(e, n) {
    const modulus = toAsn1Integer(n);
    const exponent = toAsn1Integer(e);

    // ASN.1 DER structure for RSAPublicKey
    const sequence = Buffer.concat([
        Buffer.from([0x30, modulus.length + exponent.length + 2]), // Sequence header
        Buffer.from([0x02, modulus.length]), // Integer for n
        modulus,
        Buffer.from([0x02, exponent.length]), // Integer for e
        exponent,
    ]);

    // Convert to base64 PEM format
    const base64Encoded = sequence.toString('base64');
    const pem = `-----BEGIN PUBLIC KEY-----\n${base64Encoded.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

    return pem;
}

// Function to create an RSA private key PEM from e, d, n
export function createPrivateKeyPem(e, d, n) {
    const modulus = toAsn1Integer(n);
    const exponent = toAsn1Integer(e);
    const privateExponent = toAsn1Integer(d);

    // ASN.1 DER structure for RSAPrivateKey
    const sequence = Buffer.concat([
        Buffer.from([0x30, modulus.length + exponent.length + privateExponent.length + 6]), // Sequence header
        Buffer.from([0x02, modulus.length]), // Integer for n
        modulus,
        Buffer.from([0x02, exponent.length]), // Integer for e
        exponent,
        Buffer.from([0x02, privateExponent.length]), // Integer for d
        privateExponent,
    ]);

    // Convert to base64 PEM format
    const base64Encoded = sequence.toString('base64');
    const pem = `-----BEGIN PRIVATE KEY-----\n${base64Encoded.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;

    return pem;
}

// Helper function to decode a Base64 PEM string to a Buffer
export function decodePEM(pem) {
  // Strip the PEM headers and footers
  const base64Data = pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '');
  return Buffer.from(base64Data, 'base64');
}

// Function to parse the RSAPublicKey structure and extract n and e
export function parseRSAPublicKey(pem) {
  const der = decodePEM(pem);
  let offset = 0;

  // The first byte should be 0x30 (SEQUENCE) indicating a SEQUENCE structure
  if (der[offset] !== 0x30) {
    throw new Error('Invalid public key format');
  }
  offset++;

  // Read the length of the sequence
  const sequenceLength = der[offset];
  offset += 1;

  // Read modulus (n) - INTEGER type (0x02)
  if (der[offset] !== 0x02) {
    throw new Error('Invalid public key format');
  }
  offset++;
  const nLength = der[offset];
  offset++;
  const n = der.slice(offset, offset + nLength);
  offset += nLength;

  // Read public exponent (e) - INTEGER type (0x02)
  if (der[offset] !== 0x02) {
    throw new Error('Invalid public key format');
  }
  offset++;
  const eLength = der[offset];
  offset++;
  const e = der.slice(offset, offset + eLength);

  return {
    n: n.toString('hex'), // Convert to hex string
    e: e.toString('hex')  // Convert to hex string
  };
}

// Function to parse the RSAPrivateKey structure and extract n, e, and d
export function parseRSAPrivateKey(pem) {
  const der = decodePEM(pem);
  let offset = 0;

  // The first byte should be 0x30 (SEQUENCE) indicating a SEQUENCE structure
  if (der[offset] !== 0x30) {
    throw new Error('Invalid private key format');
  }
  offset++;

  // Read the length of the sequence
  const sequenceLength = der[offset];
  offset += 1;

  // Skip the version byte (it's usually 0x00)
  offset++;

  // Read modulus (n) - INTEGER type (0x02)
  if (der[offset] !== 0x02) {
    throw new Error('Invalid private key format');
  }
  offset++;
  const nLength = der[offset];
  offset++;
  const n = der.slice(offset, offset + nLength);
  offset += nLength;

  // Read public exponent (e) - INTEGER type (0x02)
  if (der[offset] !== 0x02) {
    throw new Error('Invalid private key format');
  }
  offset++;
  const eLength = der[offset];
  offset++;
  const e = der.slice(offset, offset + eLength);
  offset += eLength;

  // Read private exponent (d) - INTEGER type (0x02)
  if (der[offset] !== 0x02) {
    throw new Error('Invalid private key format');
  }
  offset++;
  const dLength = der[offset];
  offset++;
  const d = der.slice(offset, offset + dLength);

  return {
    n: n.toString('hex'), // Convert to hex string
    e: e.toString('hex'), // Convert to hex string
    d: d.toString('hex')  // Convert to hex string
  };
}