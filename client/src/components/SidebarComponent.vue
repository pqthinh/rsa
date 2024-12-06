<template>
  <nav class="navbar">
    <div class="navbar__logo">
      <a href="/">
        <img alt="Logo" loading="lazy" width="150" height="35" src="../assets/logo/logo.svg" />
      </a>
    </div>
    <div class="navbar__menu-toggle" @click="toggleMenu">
      <div class="navbar__bar"></div>
      <div class="navbar__bar"></div>
      <div class="navbar__bar"></div>
    </div>
    <ul v-show="menuOpen" class="navbar__nav-links">
      <li>
        <a href="/tools">Tools</a>
      </li>
      <li>
        <a href="/about">About</a>
      </li>
    </ul>
  </nav>
</template>

<script>
export default {
  data() {
    return {
      menuOpen: false,
    };
  },
  methods: {
    toggleMenu() {
      this.menuOpen = !this.menuOpen;
    },
  },
};
</script>

<style scoped>
.navbar {
  display: flex;
  justify-content: space-between;
  padding: 1rem;
  background-color: #333;
  color: #fff;
}

.navbar__logo img {
  width: 150px;
}

.navbar__menu-toggle {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  height: 20px;
  cursor: pointer;
}

.navbar__bar {
  width: 20px;
  height: 3px;
  background-color: white;
}

.navbar__nav-links {
  display: flex;
  list-style-type: none;
  padding: 0;
}

.navbar__nav-links li {
  margin-right: 1rem;
}

.navbar__nav-links li a {
  color: white;
  text-decoration: none;
}
</style>
