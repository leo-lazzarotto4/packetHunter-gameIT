<template>
  <div class="app">
    <h1>🕵️‍♂️ Analyseur de fichiers PCAP</h1>

    <button @click="analyzePcap" :disabled="loading">
      {{ loading ? "🔍 Analyse en cours..." : "🚀 Lancer l'analyse" }}
    </button>

    <p v-if="loadingSuspicious && !loading">
      🧪 Chargement des activités suspectes en cours...
    </p>

    <div v-if="result && result.analysis" class="result">
      <h2>✅ Résultat de l'analyse</h2>
      <div class="dashboard">
        <div
          v-for="(details) in result.analysis"
          :key="details.mac"
          class="card"
        >
          <h3>MAC : {{ details.mac }}</h3>
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

    <template v-if="!loadingSuspicious && suspiciousActivities.length">
      <extractedFileTable :extracted_files="extracted_files" />

      <dashboard :statistics="statistics" :suspiciousActivities="suspiciousActivities" />

      <div v-if="true" class="ia-response">
        <h2>🧠 Réponse de l'analyse IA</h2>
        <p>{{ ia_response }}</p>
      </div>

      <div v-if="filterBySeverityMock('high').length" class="mt-8">
        <h2 class="text-red-500">Tableau Sévérité : High</h2>
        <analyzeTable :suspicious-activities="filterBySeverityMock('high')" />
      </div>

      <div v-if="filterBySeverityMock('medium').length" class="mt-8">
        <h2 class="text-orange-500">Tableau Sévérité : Medium</h2>
        <analyzeTable :suspicious-activities="filterBySeverityMock('medium')" />
      </div>

      <div v-if="filterBySeverityMock('low').length" class="mt-8">
        <h2 class="text-yellow-500">Tableau Sévérité : Low</h2>
        <analyzeTable :suspicious-activities="filterBySeverityMock('low')" />
      </div>
    </template>
  </div>
</template>

<script>
import axios from 'axios';
import analyzeTable from './components/analyzeTable.vue';
import dashboard from './components/dashboard.vue';
import extractedFileTable from './components/extractedFileTable.vue';
import mockData from './mockData/mockData.json';

export default {
  data() {
    return {
      result: null,
      error: null,
      loading: false,
      loadingSuspicious: false,
      suspiciousActivities: [],
      statistics: [],
      extracted_files: [],
      ia_response: "",
    };
  },
  components: {
    analyzeTable,
    dashboard,
    extractedFileTable,
  },
  methods: {
    async analyzePcap() {
      this.loading = true;
      this.loadingSuspicious = true;
      this.result = null;
      this.error = null;

      try {
        const [analyzeRes, suspiciousRes] = await Promise.all([
          axios.get('http://localhost:3000/analyze'),
          axios.get('http://localhost:3000/malware-analysis'),
        ]);

        this.result = analyzeRes.data;

        if (suspiciousRes.data && suspiciousRes.data.suspicious_activities) {
          this.suspiciousActivities = suspiciousRes.data.suspicious_activities;
          this.statistics = suspiciousRes.data.statistics || [];
          this.extracted_files = suspiciousRes.data.extracted_files || [];
          this.ia_response = suspiciousRes.data.ia_summary || "";
        } else {
          throw new Error("Format inattendu des données 'malware-analysis'");
        }
      } catch (err) {
        this.error = err.response?.data?.error || err.message;
        console.warn("Fallback aux données mockées.");
        this.suspiciousActivities = mockData.suspicious_activities;
        this.statistics = mockData.statistics;
        this.extracted_files = mockData.extracted_files;
      } finally {
        this.loading = false;
        this.loadingSuspicious = false;
      }
    },
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
  max-width: 1200px;
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

.ia-response {
  margin-top: 2rem;
  background-color: #1f2937;
  padding: 1rem;
  border-radius: 8px;
  text-align: left;
  white-space: pre-wrap;
  word-wrap: break-word;
  overflow-wrap: break-word;
  overflow-y: auto;
}

</style>
