<template>
    <div class="center">
        <div v-if="question">
            <p>{{ $t("analysis.question") }}</p>
            <div class="empty-action">
                <button class="btn" v-on:click="save_capture()">{{ $t("analysis.no_btn") }}</button> <button class="btn btn-primary" v-on:click="start_analysis()">{{ $t("analysis.yes_btn") }}</button>
            </div>
        </div>
        <div v-else-if="running">
            <img src="@/assets/loading.svg"/>
            <p class="legend" v-if="!long_waiting">{{ $t("analysis.please_wait_msg") }}</p>
            <p class="legend fade-in" v-if="long_waiting">{{ $t("analysis.some_time_msg") }}</p>
        </div>
    </div>
</template>

<script>
import router from '../router'
import axios from 'axios'

export default {
    name: 'analysis',   
    data() {
        return {
            question: true,
            running: false,
            check_alerts: false,
            long_waiting: false,
            translation: {}
        }
    },
    props: {
        capture_token: String
    },
    methods: {
        start_analysis: function() {
            this.question = false
            this.running = true
            setTimeout(function () { this.long_waiting = true }.bind(this), 15000);
            axios.get(`/api/analysis/start/${this.capture_token}`, { timeout: 60000 })
                .then(response => {
                    if(response.data.message == 'Analysis started')
                        this.check_alerts = setInterval(() => { this.get_alerts(); }, 500);
                })
                .catch(error => {
                    console.log(error);
                });
        },
        get_alerts: function() {
            axios.get(`/api/analysis/report/${this.capture_token}`, { timeout: 60000 })
                .then(response => {
                    if(response.data.message != 'No report yet'){
                        clearInterval(this.check_alerts);
                        this.long_waiting = false;
                        this.running = false;
                        router.replace({ name: 'report', 
                                         params: { alerts : response.data.alerts, 
                                                   device : response.data.device,  
                                                   capture_token : this.capture_token } });
                    }
                })
                .catch(error => {
                    console.log(error);
                });
        },
        save_capture: function() {
            var capture_token = this.capture_token
            router.replace({ name: 'save-capture', 
                             params: { capture_token: capture_token } });
        }
    }
}
</script>
