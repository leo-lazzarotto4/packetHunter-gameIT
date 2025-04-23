<script setup>
import { ref, onMounted, computed } from 'vue'
import Chart from 'primevue/chart'
import Card from 'primevue/card'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import mockData from '../mockData/mockData.json'

const stats = ref(mockData.statistics)
const activities = ref(mockData.suspicious_activities)

// Données du graphique en barres principal
const barChartData = ref({
  labels: ['Total Paquets', 'Paquets Analyzés', 'Connexions SSL', 'Requêtes HTTP', 'Requêtes DNS'],
  datasets: [{
    label: 'Statistiques Réseau',
    data: [stats.value.total_packets, stats.value.analyzed_packets, stats.value.ssl_connections, stats.value.http_requests, stats.value.dns_queries],
    backgroundColor: '#4B0082'
  }]
})

const barChartOptions = ref({
  responsive: true,
  plugins: { legend: { display: true } },
  scales: { y: { beginAtZero: true } }
})

// Activités suspectes - comptage par type
const suspiciousActivityCounts = computed(() => {
  const counts = {}
  activities.value.forEach(activity => {
    const type = activity.type
    counts[type] = (counts[type] || 0) + 1
  })
  return counts
})

// Données du graphique en barres pour activités suspectes
const suspiciousBarChartData = ref({
  labels: [],
  datasets: [{
    label: 'Activités suspectes par type',
    data: [],
    backgroundColor: '#4B0082'
  }]
})

onMounted(() => {
  const counts = suspiciousActivityCounts.value
  suspiciousBarChartData.value.labels = Object.keys(counts)
  suspiciousBarChartData.value.datasets[0].data = Object.values(counts)
})

const lineChartOptions = ref({
  responsive: true,
  plugins: { legend: { display: true } },
  scales: { y: { beginAtZero: true } }
})

function formatKey(key) {
  return key.replace(/_/g, ' ').toUpperCase()
}
</script>

<template>
  <div class="dashboard-container p-4">
    <h2 class="text-2xl mb-4">Dashboard Réseau</h2>

    <!-- Cards -->
    <div class="w-full grid grid-cols-1 sm:grid-cols-3 gap-2 md:grid-cols-3 justify-center">
      <Card v-for="(value, key) in stats" :key="key" class="m-2" :style="{ width: '15rem' }">
        <template #title>{{ formatKey(key) }}</template>
        <template #content>
          <div class="text-xl">{{ value }}</div>
        </template>
      </Card>
    </div>

    <!-- Graphiques -->
    <div class="grid grid-cols-1 gap-6 mt-8">
      <Card class="my-4 p-4">
        <template #title>Graphique des statistiques</template>
        <template #content>
          <Chart type="bar" :data="barChartData" :options="barChartOptions" style="min-height: 300px; min-width: 750px" />
        </template>
      </Card>

      <Card class="my-4 p-4">
        <template #title>Types d'activités suspectes</template>
        <template #content>
          <Chart type="bar" :data="suspiciousBarChartData" :options="barChartOptions" style="min-height: 300px; min-width: 750px" />
        </template>
      </Card>
    </div>
  </div>
</template>

<style scoped>
.dashboard-container {
  max-width: 1400px;
  margin: 0 auto;
  justify-content: center;
  align-items: center;
}
</style>
