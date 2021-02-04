<template>
  <div id="app">
    <div class="wrapper">
      <Controls />

      <div class="locale-switch">
        <select v-model="$i18n.locale">
          <option v-for="(lang, i) in $i18n.availableLocales" :key="`Lang${i}`" :value="lang">
            {{ lang }}
          </option>
        </select>
      </div>

      <transition name="fade" mode="out-in">
          <router-view />
      </transition>
    </div>
  </div>
</template>

<style>
  @import './assets/spectre.min.css';
  @import './assets/custom.css';
  
  /* Face style for router stuff. */
  .fade-enter-active,
  .fade-leave-active {
    transition-duration: 0.3s;
    transition-property: opacity;
    transition-timing-function: ease;
  }

  .fade-enter,
  .fade-leave-active {
    opacity: 0
  }

  .locale-switch {
    position: absolute;
    top: 30px;
    right: 30px;
  }
  
  .locale-switch select {
    text-transform: uppercase;
  }
</style>

<script>
  document.title = 'TinyCheck Frontend'
  import Controls from "@/components/Controls.vue"

  export default {
    name: 'app',
    components: {
        Controls
    }
  }
</script>

