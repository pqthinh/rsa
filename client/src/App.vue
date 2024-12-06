<template>
  <div id="app">
    <SidebarComponent />
    <RSAForm />
    <FooterComponent />
  </div>
</template>

<script>
import SidebarComponent from './components/SidebarComponent.vue';
import RSAForm from './components/RSAForm.vue';
import FooterComponent from './components/FooterComponent.vue';

export default {
  components: {
    SidebarComponent,
    RSAForm,
    FooterComponent,
  },
};
</script>

<style>
@import './assets/styles/styles.css';
</style>
