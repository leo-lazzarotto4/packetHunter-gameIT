<template>
  <div class="analyzeTable">
    <DataTable 
      :value="suspiciousActivities" 
      class="p-datatable-sm"
      scrollable
      scrollHeight="400px"
      responsiveLayout="scroll"
    >
      <Column field="timestamp" header="Heure" :body="formatDate" />
      <Column field="type" header="Type" />
      <Column field="src_ip" header="IP Source" />
      <Column field="dst_ip" header="IP Dest." />
      <Column field="mitre_technique" header="MITRE" />
      <Column field="severity" header="Gravité" />
    </DataTable>
  </div>
</template>

<script>
export default {
  props: {
    suspiciousActivities: Array,
  },
  computed: {
    severity() {
      // return this.suspiciousActivities.length > 0 
      //   ? this.suspiciousActivities[0].severity
      //   
      'Aucune';
    },
  },
  methods: {
    formatDate(date) {
      return new Date(date).toLocaleString();
    },
  },
};
</script>

<style scoped>
.analyzeTable {
  max-height: 400px;
  overflow-y: auto;
}
</style>
