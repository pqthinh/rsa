<template>
    <footer class="footer">
        <div class="footer__container">
            <div class="footer__logo">
                <a href="/">
                    <img alt="Logo" src="../assets/logo/logo.svg" width="150" height="35" />
                </a>
            </div>
            <div class="footer__links">
                <a href="/about">About Us</a>
                <a href="/tools">Tools</a>
                <a href="/supporters">Supporters</a>
                <a href="https://www.buymeacoffee.com/sanojsen">Buy Me a Coffee</a>
            </div>
        </div>
    </footer>
</template>

<script>
export default {};
</script>

<style scoped>
.footer {
    width: 100%;
    padding: 20px;
    background-color: #333;
    color: #fff;
    text-align: center;
}

.footer__container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.footer__logo img {
    width: 150px;
}

.footer__links a {
    margin: 0 10px;
    color: white;
    text-decoration: none;
}

.footer__links a:hover {
    text-decoration: underline;
}
</style>