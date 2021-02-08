<template>
    <div class="center" v-if="save_usb && init">
        <div class="canvas-anim" :class="{'anim-connect': !saved && !usb}" v-on:click="new_capture()">
            <div class="icon-spinner" v-if="!saved && usb"></div>
            <div class="icon-success" v-if="saved"></div>
            <div class="icon-usb"></div>
            <div class="icon-usb-plug"></div> 
        </div>
        <p class="legend" v-if="!saved && !usb"><br />{{ $t("save-capture.please_connect") }}</p>
        <p class="legend" v-if="!saved && usb"><br />{{ $t("save-capture.we_are_saving") }}</p>
        <p class="legend" v-if="saved"><br />{{ $t("save-capture.tap_msg") }}</p>
    </div>
    <div class="center" v-else-if="!save_usb && init">
        <div>
            <p class="legend">{{ $t("save-capture.capture_download") }}<br /><br /><br /></p>
            <button class="btn btn-primary" v-on:click="new_capture()">{{ $t("save-capture.start_capture_btn") }}</button>
            <iframe :src="download_url" class="frame-download"></iframe>
        </div>
    </div>
</template>

<style lang="scss">
    
    .canvas-anim {
        height: 120px;
        margin: 0 auto;
        position: relative;
        width: 205px;
        
        &.anim-connect {
            width: 300px;

            .icon-usb {
                -webkit-animation: slide-right 1s cubic-bezier(0.455, 0.030, 0.515, 0.955) infinite alternate both;
                animation: slide-right 1s cubic-bezier(0.455, 0.030, 0.515, 0.955) infinite alternate both;
            }
        }
    }

    .icon-usb {
        background: url('../assets/icon_usb.svg') no-repeat 0 0;
        background-size: 200px auto;
        display: block;
        height: 120px;
        position: absolute;
        top: 25px;
        left: 0;
        width: 200px;
        z-index: 8;
    }

    .icon-usb-plug {
        background: url('../assets/icon_plug_usb.svg') no-repeat 0 0;
        background-size: cover;
        display: block;
        height: 120px;
        position: absolute;
        top: 0;
        right: -10px;
        width: 55px;
        z-index: 9;
    }

    .icon-success {
        background: url('../assets/icon_success.svg') no-repeat 0 0;
        background-size: 80px auto;
        display: block;
        position: absolute;
        height: 120px;
        top: -25px;
        left: -40px;
        width: 80px;
        z-index: 10;
        -webkit-animation: scale-down-center 0.7s cubic-bezier(0.250, 0.460, 0.450, 0.940) both;
        animation: scale-down-center 0.7s cubic-bezier(0.250, 0.460, 0.450, 0.940) both;
    }

    .icon-spinner {
        background: url('../assets/icon_spinner.svg') no-repeat 0 0;
        background-color: #f7f8f9;
        border-radius: 40px;
        display: block;
        height: 40px;
        position: absolute;
        top: 5px;
        left: -20px;
        width: 40px;
        z-index: 10;
    }

    @-webkit-keyframes slide-right {
        0% {
            -webkit-transform: translateX(0);
                    transform: translateX(0);
        }
        100% {
            -webkit-transform: translateX(75px);
                    transform: translateX(75px);
        }
    }
    @keyframes slide-right {
        0% {
            -webkit-transform: translateX(0);
                    transform: translateX(0);
        }
        100% {
            -webkit-transform: translateX(75px);
                    transform: translateX(75px);
        }
    }

    @-webkit-keyframes scale-down-center {
        0% {
            -webkit-transform: scale(1);
                    transform: scale(1);
        }
        100% {
            -webkit-transform: scale(0.5);
                    transform: scale(0.5);
        }
    }
    @keyframes scale-down-center {
        0% {
            -webkit-transform: scale(1);
                    transform: scale(1);
        }
        100% {
            -webkit-transform: scale(0.5);
                    transform: scale(0.5);
        }
    }

</style>

<script>
import axios from 'axios'
import router from '../router'

export default {
    name: 'save-capture',
    components: {},
    data() {
        return { 
            usb: false,
            saved: false,
            save_usb: false,
            init: false,
            translation: {}
        }
    },
    props: {
        capture_token: String
    },
    methods: {
        check_usb: function() {
            axios.get(`/api/save/usb-check`, { timeout: 30000 })
                .then(response => {
                    if(response.data.status) {
                        this.usb = true
                        clearInterval(this.interval)
                        this.save_capture()
                    }
                })
        },
        save_capture: function() {
            var capture_token = this.capture_token
            axios.get(`/api/save/save-capture/${capture_token}/usb`, { timeout: 30000 })
                .then(response => {
                    if(response.data.status){
                        this.saved = true
                        this.timeout = setTimeout(() => router.push('/'), 60000);
                    } 
                })
        },
        new_capture: function() {
            clearTimeout(this.timeout);
            router.push({ name: 'generate-ap' })
        }
    },
    created: function() {
        if(window.config.download_links){
            this.init = true
            this.save_usb = false
            this.download_url = `/api/save/save-capture/${this.capture_token}/url`
        } else {
            this.init = true
            this.save_usb = true
            this.interval = setInterval(() => { this.check_usb() }, 500);
        }
    }
}
</script>