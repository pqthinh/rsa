<template>
    <main class="main-content">
        <section class="key-generator">
            <h2>Create RSA public/private keys</h2>
            <label>
                Encryption Mode:
                <select>
                    <option>2048 Bits</option>
                    <option>4096 Bits</option>
                </select>
            </label>
            <textarea placeholder="Public Key"></textarea>
            <textarea placeholder="Private Key"></textarea>
            <button>Create public/private key</button>
        </section>

        <section class="encryption">
            <h2>RSA Encryption</h2>
            <textarea placeholder="Encryption Text"></textarea>
            <textarea placeholder="Public Key"></textarea>
            <button>Encrypt</button>
        </section>
    </main>
</template>

<style scoped>
.main-content {
    flex: 1;
    padding: 20px;
}

section {
    margin-bottom: 20px;
}

textarea {
    width: 100%;
    height: 80px;
    margin-bottom: 10px;
}

button {
    display: block;
    padding: 10px;
    background-color: #007bff;
    color: #fff;
    border: none;
    cursor: pointer;
}
</style>