<template>
    <div>
        <div v-if="results">
            <div v-if="grep_keyword('STALKERWARE', 'high')" class="high-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.stalkerware_msg')"></h1>
                    <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                    <button class="btn btn-report-high" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                </div>
            </div>
            <div v-else-if="alerts.high.length >= 1" class="high-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.high_msg', { nb: $i18n.messages[$i18n.locale].report.numbers[alerts.high.length] })"></h1>
                    <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                    <button class="btn btn-report-high" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                </div>
            </div>
            <div v-else-if="grep_keyword('TRACKER', 'moderate')" class="med-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.location_msg')"></h1>
                    <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                    <button class="btn btn-report-moderate" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                </div>
            </div>
            <div v-else-if="alerts.moderate.length >= 1" class="med-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.moderate_msg', { nb: $i18n.messages[$i18n.locale].report.numbers[alerts.moderate.length] })"></h1>
                    <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                    <button class="btn btn-report-moderate" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                </div>
            </div>
            <div v-else-if="alerts.low.length >= 1" class="low-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.low_msg', { nb: $i18n.messages[$i18n.locale].report.numbers[alerts.moderate.low] })"></h1>
                    <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                    <button class="btn btn-report-low" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                </div>
            </div>
            <div v-else  class="none-wrapper">
                <div class="center">
                    <h1 class="warning-title">{{ $t("report.fine_msg") }}</h1>
                    <button class="btn btn-report-low-light" v-on:click="save_capture()">{{ $t("report.save_capture") }}</button>
                    <button class="btn btn-report-low" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                </div>
            </div>
        </div>
        <div v-else-if="show_report" class="report-wrapper">
            <div class="device-ctx">
                <h3 style="margin: 0;">{{ $t("report.report_of") }} {{device.name}}</h3>
                {{ $t("report.ip_address") }} {{device.ip_address}}<br />{{ $t("report.mac_address") }} {{device.mac_address}}
            </div>
            <ul class="alerts">
                <li class="alert" v-for="alert in alerts.high" :key="alert.message">
                    <span class="high-label">{{ $t("report.high") }}</span><span class="alert-id">{{ alert.id }}</span> 
                    <div class="alert-body">
                        <span class="title">{{ alert.title }}</span>
                        <p class="description">{{ alert.description }}</p>
                    </div>
                </li>
                <li class="alert" v-for="alert in alerts.moderate" :key="alert.message">
                    <span class="moderate-label">{{ $t("report.moderate") }}</span><span class="alert-id">{{ alert.id }}</span> 
                    <div class="alert-body">
                        <span class="title">{{ alert.title }}</span>
                        <p class="description">{{ alert.description }}</p>
                    </div>
                </li>
                <li class="alert" v-for="alert in alerts.low" :key="alert.message">
                    <span class="low-label">{{ $t("report.low") }}</span><span class="alert-id">{{ alert.id }}</span> 
                    <div class="alert-body">
                        <span class="title">{{ alert.title }}</span>
                        <p class="description">{{ alert.description }}</p>
                    </div>
                </li>
            </ul>
            <div class="columns" id="controls-analysis">
                    <div class="column col-5">
                        <button class="btn width-100" @click="$router.push('generate-ap')">{{ $t("report.start_new_capture") }}</button>
                    </div>
                    <div class="divider-vert column col-2" data-content="OR"></div>
                    <div class="column col-5">
                        <button class="btn btn btn-primary width-100" v-on:click="save_capture()">{{ $t("report.save_report") }}</button>
                    </div>
            </div>
        </div>
    </div>
</template>


<style>
#app {
    overflow-y: visible;
}   
</style>

<script>
import router from '../router'

export default {
    name: 'report',   
    data() {
        return {
            results: true,
            translation: {}
        }
    },
    props: {
        device: Object,
        alerts: Array,
        capture_token: String
    },
    methods: {
        save_capture: function() {
            var capture_token = this.capture_token
            router.replace({ name: 'save-capture', params: { capture_token: capture_token } });
        },
        new_capture: function() {
            router.push({ name: 'generate-ap' })
        },
        grep_keyword: function(kw, level){
            try {
                if(this.alerts[level].length){
                    var idx;
                    var found;
                    this.alerts[level].forEach((a) => { 
                        idx = a.title.indexOf(kw)
                        if(!found) found = idx>0;
                    }); 
                    return found; 
                } else {
                    return false;
                }
            } catch (error)
            {
                return false;
            }
        }
    }
}
</script>
