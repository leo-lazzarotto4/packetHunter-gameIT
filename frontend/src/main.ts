import { createApp } from 'vue'
import App from './App.vue'
import PrimeVue from 'primevue/config'
import 'primevue/resources/themes/lara-dark-indigo/theme.css'
import 'primevue/resources/primevue.min.css'
import 'primeicons/primeicons.css'
import 'primeflex/primeflex.css';
import Card from 'primevue/card'
import Chart from 'primevue/chart'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'

const app = createApp(App)

app.use(PrimeVue)
app.component('Card', Card)
app.component('Chart', Chart)
app.component('DataTable', DataTable)
app.component('Column', Column)

app.mount('#app')
