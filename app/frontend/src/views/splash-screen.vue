<template>
    <div class="center">
        <img src="@/assets/logo.png" id="tinycheck-logo" />
        <div class="loading loading-lg loadingsplash"></div>
    </div>
</template>

<script>
    import router from '../router'
    import axios from 'axios'

    export default {
        name: 'splash-screen',
        components: {},
        data() {
            return {
                list_ssids: [],
                internet: false
            }
        },
        methods: {
            internet_check: function() {
                axios.get('/api/network/status', { timeout: 10000 })
                    .then(response => {
                        if (response.data.internet) this.internet = true
                        if (window.config.iface_out.charAt(0) == 'e') {
                            setTimeout(function () { this.goto_home(); }.bind(this), 1000);
                        } else {
                            this.get_wifi_networks();
                        }
                    })
                    .catch(err => (console.log(err)))
            },
            get_wifi_networks: function() {
                axios.get('/api/network/wifi/list', { timeout: 10000 })
                    .then(response => { 
                        this.list_ssids = response.data.networks
                        this.goto_home();
                     })
                    .catch(err => (console.log(err)))
            },
            goto_home: function() {
                var list_ssids = this.list_ssids
                var internet   = this.internet
                router.replace({ name: 'home', params: { list_ssids: list_ssids, internet: internet } });
            }
        },
        created: function() {
            this.internet_check();
        }
    }
</script>
