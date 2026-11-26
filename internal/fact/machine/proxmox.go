package machine

// Les droits proxmox.power et proxmox.snapshot s'appuient sur un jeton
// Proxmox local, dans l'état de l'agent ; le serveur n'en voit jamais le
// secret. Sa pose revient avec #902.

// ProxmoxLocalAPI est l'API que l'agent appelle : celle de son propre hôte,
// sur la boucle locale.
const ProxmoxLocalAPI = "https://127.0.0.1:8006"
