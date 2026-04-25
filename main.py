import re
import json
from collections import defaultdict
from datetime import datetime


def detecter_instrusions(logs_bruts, seuil):

    compteur_erreurs = defaultdict(int)
    suspects = []

    for log in logs_bruts:
        """On va parcourir chaque log et extraire le nom de l'utilisateur
        on commence par definir un motif de regex pour extraire le nom de l'utilisateur"""
            
        match = re.search(r"User: (\w+)", log)
        if match and "LOGIN_FAILED" in log: #si on trouve une correspondance et que l'action est un echec de connexion:
            user = match.group(1) #on extrait le nom de l'utilisateur le group(1) recupere ce qui est entre les parenthese dans le motif regex
            compteur_erreurs[user] += 1 #on incremente le compteur d'erreurs pour cet utilisateur 

        # Affichage du nombre d'erreurs de connexion pour chaque utilisateur

    for user, erreurs in compteur_erreurs.items():
        print(f"Utilisateur: {user}, Erreurs de connexion: {erreurs}")
        if erreurs >= seuil: 
            suspects.append(user)
    with open ('suspects.json', 'w') as fichier:
        json.dump(suspects, fichier, indent = 4)

    return suspects

def analyse_securite_totale(logs_bruts, seuil_compte = 3, seuil_vitesse = 10):
    """Cette fonction combine les deux méthodes d'analyse de sécurité pour détecter les tentatives de force brute et les attaques par dictionnaire.
    Elle prend en entrée une liste de logs, un seuil pour le nombre d'erreurs de connexion et un seuil pour la vitesse des tentatives de connexion.
    Elle retourne une liste d'utilisateurs suspects qui ont dépassé les seuils définis."""
    compteur_global = defaultdict(int)
    historique_temps = defaultdict(list)
    derniers_temps = {}

    resultats = {
        "force_brute": [],
        "attaque_rapides": []
    }

    for log in logs_bruts:
        match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| User: (\w+)", log)
        if match and "LOGIN_FAILED" in log:
            date_str, user = match.groups()
            temps_acteul = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
            compteur_global[user] += 1
            historique_temps[user].append(temps_acteul)
            # Détection brute force
            if (compteur_global[user] >= seuil_compte and
                user not in resultats["force_brute"]):

                resultats["force_brute"].append(user)
               # Détection vitesse
            if len(historique_temps[user]) >= 2:

                diff = (
                    historique_temps[user][-1] -
                    historique_temps[user][-2]
                ).total_seconds()

                if (diff < seuil_vitesse and
                    user not in resultats["attaque_rapides"]):

                    resultats["attaque_rapides"].append(user)
    with open('resultats_securite.json', 'w') as fichier:
        json.dump(resultats, fichier, indent=4)
    return resultats
logs_bruts = [
    "2024-05-20 10:00:00 | User: admin | Action: LOGIN_FAILED",
    "2024-05-20 10:00:05 | User: admin | Action: LOGIN_FAILED",
    "2024-05-20 10:00:10 | User: admin | Action: LOGIN_FAILED",
    "2024-05-20 10:00:15 | User: admin | Action: LOGIN_FAILED",  # 5s -> ALERTE
    "2024-05-20 10:00:20 | User: hacker | Action: LOGIN_FAILED",
    "2024-05-20 10:00:22 | User: hacker | Action: LOGIN_FAILED"
]

bilan = analyse_securite_totale(logs_bruts)
print(f"Voici le bilan: {bilan}")
listes_suspects = detecter_instrusions(logs_bruts, 2)

if listes_suspects:
   print(f"ALERTE Tentatives de force brutes detecter pour: {listes_suspects}")