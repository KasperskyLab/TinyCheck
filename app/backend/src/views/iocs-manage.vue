<template>
    <div class="backend-content" id="content">
        <div class="column col-6 col-xs-12">
          <h3 class="s-title">Manage IOCs</h3>
          <ul class="tab tab-block">
            <li class="tab-item">
                <a href="#" v-on:click="switch_tab('bulk')" v-bind:class="{ active: tabs.bulk }">Bulk import</a>
            </li>
            <li class="tab-item">
                <a href="#" v-on:click="switch_tab('file')" v-bind:class="{ active: tabs.file }">File import</a>
            </li>
            <li class="tab-item">
                <a href="#" v-on:click="switch_tab('export')" v-bind:class="{ active: tabs.export }">Export IOCs</a>
            </li>
            <li class="tab-item">
                <a href="#" v-on:click="switch_tab('watchers')" v-bind:class="{ active: tabs.watchers }">IOCs Watchers</a>
            </li>
          </ul>
          <div v-if="tabs.export">
            <iframe :src="export_url" class="frame-export"></iframe>
          </div>
          <div v-else-if="tabs.file">
            <label class="form-upload empty" for="upload">
                <input type="file" class="upload-field" id="upload" @change="import_from_file">
                <p class="empty-title h5">Drop or select a file to import.</p>
                <p class="empty-subtitle">The file needs to be an export from a TinyCheck instance.</p>
            </label>
          </div>
          <div v-else-if="tabs.bulk">
            <div class="columns">
                <div class="column col-4 col-xs-4">
                    <div class="form-group">
                        <select class="form-select" placeholder="test" v-model="tag">
                            <option value="">IOC(s) Tag</option>
                            <option v-for="t in tags" :value="t.tag" :key="t.tag">
                                {{ t.name }}
                            </option>
                        </select>
                    </div>
                </div>
                <div class="column col-4 col-xs-4">
                    <div class="form-group">
                        <select class="form-select width-full" placeholder="test" v-model="type">
                            <option value="">IOC(s) Type</option>
                            <option value="unknown">Multiple (regex parsing)</option>
                            <option v-for="t in types" :value="t.type" :key="t.type">
                                {{ t.name }}
                            </option>
                        </select>
                    </div>
                </div>
                <div class="column col-4 col-xs-4">
                    <div class="form-group">
                        <select class="form-select width-full" placeholder="test" v-model="tlp">
                            <option value="">IOC(s) TLP</option>
                            <option value="white">TLP:WHITE</option>
                            <option value="green">TLP:GREEN</option>
                            <option value="amber">TLP:AMBER</option>
                            <option value="red">TLP:RED</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="form-group">
                <textarea class="form-input" id="input-example-3" placeholder="Paste your Indicators of Compromise here" rows="15" v-model="iocs"></textarea>
            </div>
            <div class="form-group">
                <button class="btn-primary btn col-12" v-on:click="import_from_bulk()">Import the IOCs</button>
            </div>
          </div>
          <div v-else-if="tabs.watchers">
            <div class="form-group">
                <div v-if="wiocsrc_error" class="toast toast-error">
                    ✗ {{ wiocsrc_error }}
                </div>
                <div v-else-if="wiocsrc_success" class="toast toast-success">
                    ✓ IOCs Watchers sources saved
                </div>
                <table class="table table-striped table-hover">
                    <tbody v-if="config && config.watchers && config.watchers.iocs">
                        <tr v-for="wiocsrc in config.watchers.iocs" :key="wiocsrc">
                            <td>{{ wiocsrc }}</td>
                            <td><button class="btn btn-sm" v-on:click="delete_watcher(wiocsrc)">Delete</button></td>
                        </tr>
                    </tbody>
                    <tfoot>
                        <tr>
                            <td><input class="form-input" v-model="wiocsrc" type="text" placeholder="Watcher IOCs source URL"></td>
                            <td><button class="btn btn-sm" @click="add_watcher()">Add</button></td>
                        </tr>
                    </tfoot>
                </table>
            </div>
          </div>
          <div class="form-group" v-if="imported.length>0">
            <div class="toast toast-success">
                ✓ {{imported.length}} IOC<span v-if="errors.length>1">s</span> imported successfully.
            </div>
          </div>
            <div v-if="errors.length>0">
                <div class="form-group">
                    <div class="toast toast-error">
                        ✗ {{errors.length}} IOC<span v-if="errors.length>1">s</span> not imported, see details below.
                    </div>
                </div>
                <div class="form-group">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>Indicator</th>
                                <th>Importation error</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="e in errors" v-bind:key="e.ioc">
                                <td>{{ e.ioc }}</td>
                                <td>{{ e.message }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div v-else-if="type_tag_error==true">
                <div  class="form-group">
                    <div class="toast toast-error">
                        ✗ IOC(s) not imported, see details below.
                    </div>
                </div>
                <div  class="form-group">
                    <div class="empty">
                        <p class="empty-title h5">Please select a tag and a type.</p>
                        <p class="empty-subtitle">If different IOCs types, select "Unknown (regex parsing)".</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import axios from 'axios'

export default {
    name: 'manageiocs',
    data() {
        return { 
            type:"",
            tag:"",
            tlp:"",
            iocs:"",
            types:[],
            tags:[],
            errors:[],
            imported:[],
            type_tag_error: false,
            wrong_ioc_file: false,
            tabs: { "bulk": true, "file": false, "export": false, "watchers": false },
            jwt:"",
            export_url:"",
            config: {},
            wiocsrc_error: false,
            wiocsrc_success: false,
            wiocsrc: "",
        }
    },
    props: { },
    methods: {
        import_from_bulk: function() {
            this.errors   = []
            this.imported = []
            if (this.tag != "" && this.type != "" && this.tlp != ""){
                this.iocs.match(/[^\r\n]+/g).forEach(ioc => {
                    this.import_ioc(this.tag, this.type, this.tlp, ioc);
                });
                this.iocs = "";
            } else {
                this.type_tag_error = true
            }
        },
        import_ioc: function(tag, type, tlp, ioc) {
            if (ioc != "" && ioc.slice(0,1)  != "#"){
                if("alert " != ioc.slice(0,6)) {
                    ioc = ioc.trim()
                    ioc = ioc.replace(" ", "")
                    ioc = ioc.replace("[", "")
                    ioc = ioc.replace("]", "")
                    ioc = ioc.replace("\\", "")
                    ioc = ioc.replace("(", "")
                    ioc = ioc.replace(")", "")
                }
                axios.get(`/api/ioc/add/${type.trim()}/${tag.trim()}/${tlp.trim()}/${ioc}`, { timeout: 10000, headers: {'X-Token': this.jwt} })
                .then(response => {
                    if(response.data.status){
                        this.imported.push(response.data);
                    } else if (response.data.message){
                        this.errors.push(response.data);
                    }
                })
                .catch(err => (console.log(err)))
            }
        },
        provide_watchers_iocs_config_struct: function() {
             if( !("watchers" in this.config) ) {
                 this.$set(this.config, "watchers", {});
             }
             if( !("iocs" in this.config.watchers) ) {
                 this.$set(this.config.watchers, "iocs", []);
             }
        },
        write_watchers_iocs: function() {
            this.wiocsrc_error = false;
            this.wiocsrc_success = false;
            axios.get(`/api/config/edit/watchers/iocs/${this.config.watchers.iocs.join("|")}`, {
                      timeout: 10000,
                      headers: { 'X-Token': this.jwt }
            }).then(response => {
                    if (response.data.status) {
                        console.log(response.data);
                        this.wiocsrc_success = true;
                        this.load_config();
                    } else {
                        this.wiocsrc_error = "IOCs watchers sources change failed: " + response.data;
                    }
            })
            .catch(err => { 
                   console.log(err);
                   this.wiocsrc_error = "IOCs watchers sources change failed: API could not be reached";
            });
        },
        delete_watcher: function(wiocsrc) {
            this.provide_watchers_iocs_config_struct();
            let exists = this.config.watchers.iocs.indexOf(wiocsrc);
            if(exists >= 0) {
                this.config.watchers.iocs.splice(exists, 1);
                this.write_watchers_iocs();
            } else {
                this.wiocsrc_error = "This watcher source does not exist!"
            }
        },
        add_watcher: function() {
            this.provide_watchers_iocs_config_struct();
            let exists = this.config.watchers.iocs.indexOf(this.wiocsrc);
            if(exists === -1) {
                this.config.watchers.iocs.push(this.wiocsrc);
                this.write_watchers_iocs();
            } else {
                this.wiocsrc_error = "This watcher source already exists!"
            }
        },
        enrich_selects: function() {
            axios.get(`/api/ioc/get/tags`, { timeout: 10000, headers: {'X-Token': this.jwt} })
            .then(response => {
                if(response.data.tags) this.tags = response.data.tags
            })
            .catch(err => (console.log(err)));
            axios.get(`/api/ioc/get/types`, { timeout: 10000, headers: {'X-Token': this.jwt} })
            .then(response => {
                if(response.data.types) this.types = response.data.types
            })
            .catch(err => (console.log(err)));
        },
        switch_tab: function(tab) {
            this.errors   = []
            this.imported = []

            Object.keys(this.tabs).forEach(key => {
                if( key == tab ){
                    this.tabs[key] = true
                } else {
                    this.tabs[key] = false
                }
            });
        },
        import_from_file: function(ev) {
            this.errors   = []
            this.imported = []
            
            const file = ev.target.files[0];
            const reader = new FileReader();

            reader.onload = e => this.$emit("load", e.target.result);
            reader.onload = () => {
                try {
                    JSON.parse(reader.result).iocs.forEach(ioc => {
                        this.import_ioc(ioc["tag"], ioc["type"], ioc["tlp"], ioc["value"])
                    })
                } catch (error) {
                    this.wrong_ioc_file = true
                }

            } 
            reader.readAsText(file);
        },
        async get_jwt(){
            await axios.get(`/api/get-token`, { timeout: 10000 })
                .then(response => {
                    if(response.data.token){
                        this.jwt = response.data.token
                    }
                })
            .catch(err => (console.log(err)))
        },
        load_config: function() {
            axios.get(`/api/config/list`, {
                    timeout: 10000,
                    headers: { 'X-Token': this.jwt }
                }).then(response => {
                    if (response.data) {
                        this.config = response.data
                    }
                })
                .catch(err => (console.log(err)))
        }
    },
    created: function() {
        this.get_jwt().then(() => {
           this.enrich_selects(); 
           this.load_config();
           this.export_url = `/api/ioc/export?token=${this.jwt}`
        });
    }
}
</script>