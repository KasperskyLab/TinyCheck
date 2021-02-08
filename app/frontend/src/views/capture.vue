<template>
    <div class="capture-wrapper">
        <svg id="sparkline" stroke-width="3" :width="sparkwidth" :height="sparkheight" v-if="sparklines"></svg>
        <div class="center">
            <div class="footer">
                <h3 class="timer">{{timer_hours}}:{{timer_minutes}}:{{timer_seconds}}</h3>
                <p>{{$t("capture.intercept_coms_msg")}} {{device_name}}.</p>
                <div class="empty-action">
                    <button class="btn" :class="[ loading ? 'loading' : 'btn-primary', ]" v-on:click="stop_capture()">{{$t("capture.stop_btn")}}</button>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import axios from 'axios'
import router from '../router'
import sparkline from '@fnando/sparkline'

export default {
    name: 'capture',
    components: {},
    data() {
        return {
            timer_hours: "00",
            timer_minutes: "00",
            timer_seconds: "00",
            loading: false,
            stats_interval: false,
            chrono_interval: false,
            sparklines: false,
            translation: {}
        }
    },
    props: {
        capture_token: String,
        device_name: String
    },
    methods: {
        set_chrono: function() {
            this.chrono_interval = setInterval(() => { this.chrono(); }, 10);
        },
        stop_capture: function() {
            this.loading = true
            axios.get('/api/network/ap/stop', { timeout: 30000 })
            axios.get('/api/capture/stop', { timeout: 30000 })
                .then(response => (this.handle_finish(response.data)))
        },
        get_stats: function() {
            axios.get('/api/capture/stats', { timeout: 30000 })
                .then(response => (this.handle_stats(response.data)))
        },
        handle_stats: function(data) {
            if (data.packets.length) sparkline(document.querySelector('#sparkline'), data.packets);
        },
        handle_finish: function(data) {
            clearInterval(this.chrono_interval);
            clearInterval(this.stats_interval);
            if (data.status) {
                this.loading = false
                var capture_token = this.capture_token
                router.replace({ name: 'analysis', params: { capture_token: capture_token } });
            }
        },
        chrono: function() {
            var time = Date.now() - this.capture_start
            this.timer_hours = Math.floor(time / (60 * 60 * 1000));
            this.timer_hours = (this.timer_hours < 10) ? '0' + this.timer_hours : this.timer_hours
            time = time % (60 * 60 * 1000);
            this.timer_minutes = Math.floor(time / (60 * 1000));
            this.timer_minutes = (this.timer_minutes < 10) ? '0' + this.timer_minutes : this.timer_minutes
            time = time % (60 * 1000);
            this.timer_seconds = Math.floor(time / 1000);
            this.timer_seconds = (this.timer_seconds < 10) ? '0' + this.timer_seconds : this.timer_seconds
        },
        setup_sparklines: function() {
            axios.get('/api/misc/config', { timeout: 60000 })
                .then(response => {
                    if(response.data.sparklines){
                        this.sparklines = true
                        this.sparkwidth = window.screen.width + 'px';
                        this.sparkheight = Math.trunc(window.screen.height / 5) + 'px';
                        this.stats_interval = setInterval(() => { this.get_stats(); }, 500);
                    }
                })
                .catch(error => {
                    console.log(error)
                });
        },
    },
    created: function() {
        // Get the config for the sparklines.
        this.setup_sparklines()
        
        // Start the chrono and get the first stats.
        this.capture_start = Date.now()
        this.set_chrono();
    }
}
</script>
