package machine

// VzdumpBinary est vzdump, que l'agent cherche avant d'accepter
// backup.produce=proxmox-vzdump (availability). Sa préparation sur l'hôte
// (script, règle sudo, drop-in) revient avec la pose du jeton Proxmox (#902).
const VzdumpBinary = "/usr/bin/vzdump"
