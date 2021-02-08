<template>
  <div id="app">
    <div class="wrapper">
      <Controls />
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
</style>

<script>
  import axios from 'axios'
  import Controls from "@/components/Controls.vue"
  
  document.title = 'TinyCheck Frontend'

  export default {
    name: 'app',
    components: {
        Controls
    },
    methods: {
        set_lang: function() {
            if (window.config.user_lang) {
                var lang = window.config.user_lang
                if (Object.keys(this.$i18n.messages).includes(lang)) {
                    this.$i18n.locale = lang
                    document.querySelector('html').setAttribute('lang', lang)
                }
            }
        },
        get_config: function() {
            axios.get('/api/misc/config', { timeout: 60000 })
            .then(response => { 
              this.set_lang();
              window.config = response.data 
            })
            .catch(error => { console.log(error) });
        }
    },
    created: function() {
        window.config = {}
        this.get_config();
    }
  }
</script>

