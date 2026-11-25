// Package machine porte le modèle Machine de Kagu : les machines, la
// machine Kagu comprise, et leurs agents ; l'enrôlement par jeton à
// usage unique, les droits cochés à l'installation, l'authentification de
// l'agent par signature Ed25519, sa révocation, et les sessions ouvertes. Il
// ne parle ni HTTP ni SQL : le web et le store le font.
package machine
