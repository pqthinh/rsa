<template>
    <div class="layout-container">
        <h1 class="title">RSA Encryption / Decryption Tool</h1>

        <!-- RSA Key Generation -->
        <section class="rsa-section">
            <h2>Create RSA public / private keys</h2>
            <div class="form-control">
                <label>Encryption Mode</label>
                <select v-model="selectedBits">
                    <option>512 Bits</option>
                    <option>1024 Bits</option>
                    <option>2048 Bits</option>
                    <option>4096 Bits</option>
                    <option>8192 Bits</option>
                    <option>16384 Bits</option>
                </select>
            </div>
            <div class="key-container">
                <div class="form-control">
                    <label>Public Key</label>
                    <textarea v-model="publicKey" rows="10" placeholder="Public Key"></textarea>
                </div>
                <div class="form-control">
                    <label>Private Key</label>
                    <textarea v-model="privateKey" rows="10" placeholder="Private Key"></textarea>
                </div>
            </div>
            <button class="button" @click="generateKeys">Create public / Private key</button>
        </section>

        <!-- RSA Encryption -->
        <section class="rsa-section">
            <h2>RSA Encryption</h2>
            <div class="form-container">
                <div class="form-control">
                    <label>Encryption Text</label>
                    <textarea v-model="encryptionText" rows="5" placeholder="Encryption Text"></textarea>
                </div>
                <div class="form-control">
                    <label>Public Key</label>
                    <textarea v-model="encryptionKey" rows="5" placeholder="Public key"></textarea>
                </div>
                
            </div>
            <button class="button" @click="encryptText">Encrypt</button>
            <div class="form-control">
                <label>Encrypted Text</label>
                <textarea v-model="encryptedText" rows="20" readonly></textarea>
            </div>
        </section>

        <!-- RSA Decryption -->
        <section class="rsa-section">
            <h2>RSA Decryption</h2>
            <div class="form-container">
                <div class="form-control">
                    <label>Encrypted Text</label>
                    <textarea v-model="decryptionText" rows="5" placeholder="Encrypted Text"></textarea>
                </div>
                <div class="form-control">
                    <label>Private Key</label>
                    <textarea v-model="decryptionKey" rows="5" placeholder="Private key"></textarea>
                </div>
                
            </div>
            <button class="button" @click="decryptText">Decrypt</button>
            <div class="form-control">
                <label>Decrypted Text</label>
                <textarea v-model="decryptedText" rows="20" readonly></textarea>
            </div>
        </section>
    </div>
</template>

<script>
export default {
    data() {
        return {
            selectedBits: '512 Bits',
            publicKey: '',
            privateKey: '',
            encryptionText: '',
            encryptionKey: '',
            encryptedText: '',
            decryptionText: '',
            decryptionKey: '',
            decryptedText: '',
        };
    },
    methods: {
        generateKeys() {
            // Logic to generate RSA keys
            console.log('Generating keys for', this.selectedBits);
        },
        encryptText() {
            // Encrypt the encryptionText using encryptionKey
            this.encryptedText = 'Encrypted: ' + this.encryptionText; // Placeholder logic
        },
        decryptText() {
            // Decrypt the decryptionText using decryptionKey
            this.decryptedText = 'Decrypted: ' + this.decryptionText; // Placeholder logic
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
}

button {
    background-color: #28a745;
    color: white;
    padding: 10px 20px;
    border: none;
    cursor: pointer;
    border-radius: 4px;
}

button:hover {
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

</style>