<script setup>
import { ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import mockData from '../mockData/mockData.json'

const props = defineProps({
  extracted_files: Object,
})

// Liste des fichiers extraits
const files = ref(props.extracted_files.files || [])

// Fonction pour formater le timestamp
function formatTimestamp(timestamp) {
  return new Date(timestamp * 1000).toLocaleString("fr-FR")
}

// Fonction pour styliser le tag "Malicious"
function getMaliciousTagStyle(isMalicious) {
  return {
    value: isMalicious ? 'Malicieux' : 'Sain',
    severity: isMalicious ? 'danger' : 'success'
  }
}
</script>

<template>
  <div class="p-4">
    <h3 class="text-xl mb-4">📂 Fichiers Extraits</h3>
    <DataTable :value="files" paginator :rows="10" responsiveLayout="scroll" stripedRows>
      <Column field="filename" header="Nom du fichier" />
      <Column field="src_ip" header="IP Source" />
      <Column field="dst_ip" header="IP Destination" />
      <Column header="Temps">
        <template #body="{ data }">
          {{ formatTimestamp(data.timestamp) }}
        </template>
      </Column>
      <Column header="Malicieux">
        <template #body="{ data }">
          <Tag :value="getMaliciousTagStyle(data.malicious).value"
               :severity="getMaliciousTagStyle(data.malicious).severity" />
        </template>
      </Column>
    </DataTable>
  </div>
</template>
