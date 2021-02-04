import Vue from 'vue'
import VueI18n from 'vue-i18n'
import axios from 'axios'

Vue.use(VueI18n)

export const i18n = new VueI18n({
  locale: 'en',
  fallbackLocale: 'en',
  messages: {
    'en': require('@/locales/en.json'),
    'fr': require('@/locales/fr.json')
  }
})

const browserLang = navigator.language.split('-')[0];

if (['en', 'fr'].indexOf(browserLang) > -1) {
    setI18nLanguage(browserLang);
} else {
    setI18nLanguage('en');
}

function setI18nLanguage (lang) {
  i18n.locale = lang
  axios.defaults.headers.common['Accept-Language'] = lang
  document.querySelector('html').setAttribute('lang', lang)
  return lang
}
