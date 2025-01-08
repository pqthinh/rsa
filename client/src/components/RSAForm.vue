<template>
    <div class="layout-container">
        <h1 class="title">RSA Encryption / Decryption Tool</h1>

        <!-- RSA Key Generation -->
        <section class="rsa-section">
            <h2>Create RSA Public / Private Keys</h2>
            <div class="form-control">
                <label>Encryption Mode</label>
                <select v-model="selectedBits">
                    <option value="1024">1024 Bits</option>
                    <option value="2048">2048 Bits</option>
                    <option value="4096">4096 Bits</option>
                    <option value="8192">8192 Bits</option>
                    <option value="16384">16384 Bits</option>
                    <option value="32768">32768 Bits</option>
                </select>
            </div>
            <div class="key-container">
                <div class="form-control">
                    <label>Public Key</label>
                    <textarea v-model="publicKey" rows="10" placeholder="Public Key" readonly></textarea>
                </div>
                <div class="form-control">
                    <label>Private Key</label>
                    <textarea v-model="privateKey" rows="10" placeholder="Private Key" readonly></textarea>
                </div>
            </div>
            <button class="button" @click="generateKeysFunction" :disabled="isGeneratingKeys">
                {{ isGeneratingKeys ? 'Generating...' : 'Create Public Key / Private Key' }}
            </button>
            <p v-if="keyGenerationError" class="error-message">{{ keyGenerationError }}</p>
        </section>

        <!-- RSA Encryption -->
        <section class="rsa-section">
            <h2>RSA Encryption</h2>
            <div class="form-container">
                <div class="form-control">
                    <label>Plaintext</label>
                    <textarea v-model="encryptionText" rows="5" placeholder="Enter text to encrypt"></textarea>
                </div>
                <div class="form-control">
                    <label>Public Key</label>
                    <textarea v-model="encryptionKey" rows="5" placeholder="Paste Public Key"></textarea>
                </div>
            </div>
            <button class="button" @click="encryptText" :disabled="isEncrypting">
                {{ isEncrypting ? 'Encrypting...' : 'Encrypt' }}
            </button>
            <div class="form-control">
                <label>Encrypted Text</label>
                <textarea v-model="encryptedText" rows="10" readonly></textarea>
            </div>
            <p v-if="encryptionError" class="error-message">{{ encryptionError }}</p>
        </section>

        <!-- RSA Decryption -->
        <section class="rsa-section">
            <h2>RSA Decryption</h2>
            <div class="form-container">
                <div class="form-control">
                    <label>Encrypted Text</label>
                    <textarea v-model="decryptionText" rows="5" placeholder="Paste Encrypted Text"></textarea>
                </div>
                <div class="form-control">
                    <label>Private Key</label>
                    <textarea v-model="decryptionKey" rows="5" placeholder="Paste Private Key"></textarea>
                </div>
            </div>
            <button class="button" @click="decryptText" :disabled="isDecrypting">
                {{ isDecrypting ? 'Decrypting...' : 'Decrypt' }}
            </button>
            <div class="form-control">
                <label>Decrypted Text</label>
                <textarea v-model="decryptedText" rows="10" readonly></textarea>
            </div>
            <p v-if="decryptionError" class="error-message">{{ decryptionError }}</p>
        </section>
    </div>
</template>

<script>
import axios from 'axios';

export default {
    data() {
        return {
            selectedBits: '2048', // Default key size
            publicKey: '',
            privateKey: '',
            encryptionText: '',
            encryptionKey: '',
            encryptedText: '',
            decryptionText: '',
            decryptionKey: '',
            decryptedText: '',
            // Loading states
            isGeneratingKeys: false,
            isEncrypting: false,
            isDecrypting: false,
            // Error messages
            keyGenerationError: '',
            encryptionError: '',
            decryptionError: '',
        };
    },
    methods: {
        /**
         * Generate RSA Public and Private Keys
         */
        async generateKeysFunction() {
            this.isGeneratingKeys = true;
            this.keyGenerationError = '';
            this.publicKey = '';
            this.privateKey = '';

            try {
                const response = await axios.post('http://localhost:18080/generate_keys', {
                    keysize: parseInt(this.selectedBits),
                }, {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                });

                if (response.status === 200 && response.data) {
                    this.publicKey = response.data.public_key || '';
                    this.privateKey = response.data.private_key || '';
                } else {
                    this.keyGenerationError = 'Unexpected response from the server.';
                }
            } catch (error) {
                console.error('Error generating keys:', error);
                if (error.response) {
                    // Server responded with a status other than 2xx
                    this.keyGenerationError = `Error ${error.response.status}: ${error.response.statusText}`;
                } else if (error.request) {
                    // No response received
                    this.keyGenerationError = 'No response from the server. Please ensure the server is running.';
                } else {
                    // Other errors
                    this.keyGenerationError = 'An error occurred while generating keys.';
                }
            } finally {
                this.isGeneratingKeys = false;
            }
        },

        /**
         * Encrypt plaintext using the provided public key
         */
        async encryptText() {
            // Reset previous outputs and errors
            this.encryptedText = '';
            this.encryptionError = '';

            // Validate inputs
            if (!this.encryptionKey.trim()) {
                this.encryptionError = 'Public key is required for encryption.';
                return;
            }

            if (!this.encryptionText.trim()) {
                this.encryptionError = 'Plaintext is required for encryption.';
                return;
            }

            this.isEncrypting = true;

            try {
                const response = await axios.post('http://localhost:18080/encrypt', {
                    public_key: this.encryptionKey.trim(),
                    plaintext: this.encryptionText.trim(),
                }, {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                });

                if (response.status === 200 && response.data) {
                    this.encryptedText = response.data.encrypted_text || '';
                } else {
                    this.encryptionError = 'Unexpected response from the server.';
                }
            } catch (error) {
                console.error('Error encrypting text:', error);
                if (error.response) {
                    this.encryptionError = `Error ${error.response.status}: ${error.response.statusText}`;
                } else if (error.request) {
                    this.encryptionError = 'No response from the server. Please ensure the server is running.';
                } else {
                    this.encryptionError = 'An error occurred while encrypting the text.';
                }
            } finally {
                this.isEncrypting = false;
            }
        },

        /**
         * Decrypt encrypted text using the provided private key
         */
        async decryptText() {
            // Reset previous outputs and errors
            this.decryptedText = '';
            this.decryptionError = '';

            // Validate inputs
            if (!this.decryptionKey.trim()) {
                this.decryptionError = 'Private key is required for decryption.';
                return;
            }

            if (!this.decryptionText.trim()) {
                this.decryptionError = 'Encrypted text is required for decryption.';
                return;
            }

            this.isDecrypting = true;

            try {
                const response = await axios.post('http://localhost:18080/decrypt', {
                    private_key: this.decryptionKey.trim(),
                    encrypted_text: this.decryptionText.trim(),
                }, {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                });

                if (response.status === 200 && response.data) {
                    this.decryptedText = response.data.decrypted_text || '';
                } else {
                    this.decryptionError = 'Unexpected response from the server.';
                }
            } catch (error) {
                console.error('Error decrypting text:', error);
                if (error.response) {
                    this.decryptionError = `Error ${error.response.status}: ${error.response.statusText}`;
                } else if (error.request) {
                    this.decryptionError = 'No response from the server. Please ensure the server is running.';
                } else {
                    this.decryptionError = 'An error occurred while decrypting the text.';
                }
            } finally {
                this.isDecrypting = false;
            }
        },
    },
};
</script>

<style scoped>
.layout-container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.title {
    text-align: center;
}

.rsa-section {
    margin-bottom: 30px;
}

.key-container,
.form-container {
    display: flex;
    justify-content: space-between;
}

.form-control {
    width: 48%;
    margin-bottom: 10px;
}

textarea {
    width: 100%;
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 4px;
    resize: vertical;
}

button {
    background-color: #28a745;
    color: white;
    padding: 10px 20px;
    border: none;
    cursor: pointer;
    border-radius: 4px;
    font-size: 16px;
}

button:disabled {
    background-color: #6c757d;
    cursor: not-allowed;
}

button:hover:not(:disabled) {
    background-color: #218838;
}

.form-container {
    background-color: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    margin-bottom: 20px;
}

.form-container label {
    display: block;
    margin-bottom: 5px;
    font-weight: 500;
    color: #333;
}

.form-container input,
.form-container textarea {
    width: 100%;
    padding: 8px;
    margin-bottom: 15px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
}

.form-container input:focus,
.form-container textarea:focus {
    outline: none;
    border-color: #28a745;
    box-shadow: 0 0 0 2px rgba(40, 167, 69, 0.25);
}

.error-message {
    color: red;
    margin-top: 10px;
}
</style>
