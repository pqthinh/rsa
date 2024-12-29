sau khi nâng cấp: 
### 32768

Time taken to generate keys: 91.4876 seconds
Saving keys to mykey.pub and mykey.key
Time taken to save keys: 0.00161771 seconds
Keys generated and saved successfully.
Encrypting plaintext.txt to ciphertext.bin using mykey.pub...
Encryption completed successfully.
Time taken to encrypt: 0.00211654 seconds
Decrypting ciphertext.bin to decrypted.txt using mykey.key...
Decryption completed successfully.
Time taken to decrypt: 2.39127 seconds
Verifying decrypted.txt...
Verification successful: decrypted.txt matches plaintext.txt

### 16384
Time taken to generate keys: 6.90473 seconds
Saving keys to mykey.pub and mykey.key
Time taken to save keys: 0.00181971 seconds
Keys generated and saved successfully.
Encrypting plaintext.txt to ciphertext.bin using mykey.pub...
Encryption completed successfully.
Time taken to encrypt: 0.000847708 seconds
Decrypting ciphertext.bin to decrypted.txt using mykey.key...
Decryption completed successfully.
Time taken to decrypt: 0.403766 seconds
Verifying decrypted.txt...
Verification successful: decrypted.txt matches plaintext.txt


### 8192
Time taken to generate keys: 2.09377 seconds
Saving keys to mykey.pub and mykey.key
Time taken to save keys: 0.000333417 seconds
Keys generated and saved successfully.
Encrypting plaintext.txt to ciphertext.bin using mykey.pub...
Encryption completed successfully.
Time taken to encrypt: 0.000514875 seconds
Decrypting ciphertext.bin to decrypted.txt using mykey.key...
Decryption completed successfully.
Time taken to decrypt: 0.0691598 seconds
Verifying decrypted.txt...
Verification failed: decrypted.txt does not match plaintext.txt

### 4096
Time taken to generate keys: 0.361323 seconds
Saving keys to mykey.pub and mykey.key
Time taken to save keys: 0.000329167 seconds
Keys generated and saved successfully.
Encrypting plaintext.txt to ciphertext.bin using mykey.pub...
Encryption completed successfully.
Time taken to encrypt: 0.000362708 seconds
Decrypting ciphertext.bin to decrypted.txt using mykey.key...
Decryption completed successfully.
Time taken to decrypt: 0.0109595 seconds
Verifying decrypted.txt...
Verification successful: decrypted.txt matches plaintext.txt

### 2048
Time taken to generate keys: 0.033718 seconds
Saving keys to mykey.pub and mykey.key
Time taken to save keys: 0.000320167 seconds
Keys generated and saved successfully.
Encrypting plaintext.txt to ciphertext.bin using mykey.pub...
Encryption completed successfully.
Time taken to encrypt: 0.000376333 seconds
Decrypting ciphertext.bin to decrypted.txt using mykey.key...
Decryption completed successfully.
Time taken to decrypt: 0.00294888 seconds
Verifying decrypted.txt...
Verification successful: decrypted.txt matches plaintext.txt

### 1024
Time taken to generate keys: 0.00907683 seconds
Saving keys to mykey.pub and mykey.key
Time taken to save keys: 0.000575959 seconds
Keys generated and saved successfully.
Encrypting plaintext.txt to ciphertext.bin using mykey.pub...
Encryption completed successfully.
Time taken to encrypt: 0.000698041 seconds
Decrypting ciphertext.bin to decrypted.txt using mykey.key...
Decryption completed successfully.
Time taken to decrypt: 0.00105087 seconds
Verifying decrypted.txt...
Verification successful: decrypted.txt matches plaintext.txt

--- chua nang cap
### k=32768:
không ra kết quả trong 2 tiếng

### k=16384:
Đã lưu khóa công khai vào [mykey.pub]
Đã lưu khóa bí mật  vào [mykey.key]

Thời gian tạo khóa: 130313 ms

=== MA HOA FILE ===
Đã mã hóa file [plaintext.txt] => [cipher.dat]
Thời gian mã hóa: 183 ms

=== GIAI MA FILE ===
Đã giải mã file [cipher.dat] => [plaintext_dec.txt]
Thời gian giải mã: 773 ms

Nội dung file giải mã giống với file gốc!

#### kết quả với k=8192:
Đã lưu khóa công khai vào [mykey.pub]
Đã lưu khóa bí mật  vào [mykey.key]

Thời gian tạo khóa: 56186 ms

=== MA HOA FILE ===
Đã mã hóa file [plaintext.txt] => [cipher.dat]
Thời gian mã hóa: 33 ms

=== GIAI MA FILE ===
Đã giải mã file [cipher.dat] => [plaintext_dec.txt]
Thời gian giải mã: 128 ms

Nội dung file giải mã giống với file gốc!

### kết quả với k=4096:


### kết quả với k=2048:


### kết quả với k=1024:

### kết quả với k=512:

### kết quả với k=256: