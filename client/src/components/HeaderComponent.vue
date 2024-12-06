<template>
    <header class="header">
        <i>
            <slot name="icon"></slot>
        </i>
        <h1>RSA Encryption / Decryption Tool</h1>
    </header>
</template>

<style scoped>
.header {
    display: flex;
    align-items: center;
    padding: 10px;
    background-color: #f5f5f5;
}

.logo {
    width: 50px;
    margin-right: 15px;
}
</style>