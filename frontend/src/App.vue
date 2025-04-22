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

    <div v-if="result && result.ia_response" class="ia-response">
      <h2>🧠 Réponse de l'IA</h2>
      <pre>{{ result.ia_response }}</pre>
    </div>

    <div v-if="error" class="error">
      <strong>Erreur :</strong> {{ error }}
    </div>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      result: null,
      error: null,
      loading: false,
    };
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
  },
};
</script>

<style>
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
  background-color: #007bff;
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
  background-color: #f0fdf4;
  color: #065f46;
}

.dashboard {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.card {
  background: #ffffff;
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
  background-color: #fff8e1;
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
  white-space: pre-wrap; /* Permet au texte de se casser au lieu de dépasser */
  word-wrap: break-word; /* Force le texte long à être coupé si nécessaire */
  overflow-wrap: break-word; /* Supporte également les navigateurs modernes */
  overflow-y: auto;
}


.error {
  margin-top: 2rem;
  padding: 1rem;
  background-color: #ffebee;
  color: #c62828;
  border-radius: 8px;
}
</style>
