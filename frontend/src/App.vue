<template>
  <div class="app">
    <h1>🕵️‍♂️ Analyseur de fichiers PCAP</h1>

    <button @click="analyzePcap" :disabled="loading">
      {{ loading ? "🔍 Analyse en cours..." : "🚀 Lancer l'analyse" }}
    </button>

    <div v-if="result && result.analysis" class="result">
      <h2>✅ Résultat de l'analyse</h2>
      <div class="dashboard">
        <div
          v-for="(details, mac) in result.analysis"
          :key="mac"
          class="card"
        >
          <h3>MAC : {{ mac }}</h3>
          <ul>
            <li><strong>IP :</strong> {{ details.ip || "N/A" }}</li>
            <li><strong>Host :</strong> {{ details.hostname || "N/A" }}</li>
            <li><strong>Utilisateur :</strong> {{ details.username || "N/A" }}</li>
          </ul>
        </div>
      </div>
    </div>

    <div v-if="result && result.api_response" class="flag">
      <h2>🏁 FLAG trouvé</h2>
      <p>{{ result.api_response.flag }}</p>
    </div>

    <div v-if="error" class="error">
      <strong>Erreur :</strong> {{ error }}
    </div>

    <dashboard></dashboard>

    <!-- Filtrage des données mockées -->
    <div v-if="filterBySeverityMock('low').length > 0" class="mt-8">
      <h2 class="text-yellow-500">Tableau Sévérité : Low</h2>
      <analyzeTable :suspicious-activities="filterBySeverityMock('low')" />
    </div>

    <div v-if="filterBySeverityMock('medium').length > 0" class="mt-8">
      <h2 class="text-orange-500">Tableau Sévérité : Medium</h2>
      <analyzeTable :suspicious-activities="filterBySeverityMock('medium')" />
    </div>

    <div v-if="filterBySeverityMock('high').length > 0" class="mt-8">
      <h2 class="text-red-500">Tableau Sévérité : High</h2>
      <analyzeTable :suspicious-activities="filterBySeverityMock('high')" />
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import analyzeTable from './components/analyzeTable.vue';
import mockData from './mockData/mockData.json';
import dashboard from './components/dashboard.vue'

export default {
  data() {
    return {
      result: null, // Données provenant de l'API
      error: null,
      loading: false,
      suspiciousActivities: [],  // Données filtrées des activités suspectes
    };
  },
  components: {
    analyzeTable,
    dashboard
  },
  created() {
    this.loadMockData();  // Charger les données mockées dès la création du composant
  },
  methods: {
    async analyzePcap() {
      this.loading = true;
      this.result = null;
      this.error = null;

      try {
        const response = await axios.get('http://localhost:3000/analyze');
        this.result = response.data;
        console.log("Réponse reçue :", response.data);
      } catch (err) {
        this.error = err.response?.data?.error || err.message;
      } finally {
        this.loading = false;
      }
    },
    // Charger les données mockées depuis le fichier JSON
    loadMockData() {
      // Ici, on charge les données directement depuis mockData.json
      this.suspiciousActivities = mockData.suspicious_activities;
    },
    // Filtrer les activités en fonction de la sévérité
    filterBySeverityMock(severity) {
      return this.suspiciousActivities.filter(activity => activity.severity === severity);
    },
  },
};
</script>

<style scoped>
.app {
  font-family: Arial, sans-serif;
  padding: 2rem;
  max-width: 900px;
  margin: auto;
  text-align: center;
}

button {
  padding: 1rem 2rem;
  font-size: 1.1rem;
  cursor: pointer;
  background-color: #4B0082;
  border: none;
  color: white;
  border-radius: 5px;
  margin-top: 1rem;
}

button:disabled {
  background-color: #cccccc;
  cursor: not-allowed;
}

.result {
  margin-top: 2rem;
  padding: 1rem;
  border-radius: 8px;
  background-color: #1f2937;
  color: #065f46;
}

.dashboard {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.card {
  background: #b0b0b0;
  border: 1px solid #e0e0e0;
  padding: 1rem;
  border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.1);
  text-align: left;
}

ul {
  padding-left: 0;
  list-style: none;
}

.flag {
  margin-top: 2rem;
  background-color: #1f2937;
  padding: 1rem;
  border-radius: 8px;
  color: #ff8f00;
  font-weight: bold;
}

.ia-response {
  margin-top: 2rem;
  background-color: #e3f2fd;
  padding: 1rem;
  border-radius: 8px;
  color: #0d47a1;
  text-align: left;
  white-space: pre-wrap;
  word-wrap: break-word;
  overflow-wrap: break-word;
  overflow-y: auto;
}

.error {
  margin-top: 2rem;
  padding: 1rem;
  background-color: #ffebee;
  color: #c62828;
  border-radius: 8px;
}

.text-red-500 {
    color: var(--red-600) !important;
}
.text-yellow-500 {
    color: var(--yellow-600) !important;
}
.text-orange-500 {
    color: var(--orange-600) !important;
}
</style>
