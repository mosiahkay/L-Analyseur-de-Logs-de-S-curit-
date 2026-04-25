import re
import json
from collections import defaultdict

def detecter_instrusions(logs_bruts, suspects, seuil):

    compteur_erreurs = defaultdict(int)
    suspects = []
    seuil = 2

    """on va commencer a par verifier si la cle existe"""

    tentative = {}

    user = "admin"
    if user not in tentative:
        """on initialise a 0 s'il n'existe pas"""
        tentative[user] = 0 
    tentative[user] += 1 #maintenant on incremente le compteur de tentative pour l'utilisateur "admin"

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
        if user not in compteur_erreurs:
           compteur_erreurs[user] = 0 #on initialise le compteur d'erreurs pour cet utilisateur à 0

        for user, erreurs in compteur_erreurs.items():
            if erreurs > seuil: 
                suspects.append(user)
    with open ('suspects.json', 'w') as fichier:
        json.dump(suspects, fichier)

    return suspects


logs_bruts = [
    "User: admin | Action: LOGIN_FAILED",
    "User: guest | Action: LOGIN_SUCCESS",
    "User: admin | Action: LOGIN_FAILED",
    "User: hacker | Action: LOGIN_FAILED",
    "User: admin | Action: LOGIN_FAILED",
    "User: hacker | Action: LOGIN_FAILED"
]

listes_suspects = detecter_instrusions(logs_bruts, 2)

if listes_suspects:
    print(f"ALERTE Tentatives de force brutes detecter pour: {listes_suspects}")