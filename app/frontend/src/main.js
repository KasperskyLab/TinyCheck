import Vue from 'vue'
import App from './App.vue'
import router from './router'
import { i18n } from '@/plugins/i18n'

Vue.config.productionTip = true
Vue.config.devtools = true

new Vue({
  router,
  i18n,
  render: h => h(App)
}).$mount('#app')