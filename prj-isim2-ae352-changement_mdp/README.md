# [AE352] Changement des mots de passe

Le cas d'usage permet de changer le mot de passe, au choix:
- d'un compte défini sur une liste de machine,
- d'un compte défini sur un inventaire,
- de tous les comptes arrivant a expiration sur une liste de machine,
- de tous les comptes arrivant a expiration sur un inventaire.

## Prérequis et dépendances

Le module custom keepass (dans le repo mod-isim2-keepass) doit être présent dans le venv/EE.

## Usage

Variables d'entrées:
- (facultatif) ansible_limit: doit être défini pour limiter l'execution a une liste de machine plutot qu'a l'inventaire général.
- (facultatif) change_mdp_user_to_update: doit être défini pour limiter l'execution a un compte défini plutot qu'a tous les comptes arrivant a expiration.
- use_case_environment: (DEV|PRD) environnement d'execution du cas d'usage.
- use_case_report_email: liste de mails (comma separated) qui recevront le rapport d'execution.