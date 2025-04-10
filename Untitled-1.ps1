<#
.SYNOPSIS
    Récupère les événements d'ouverture, de fermeture, de verrouillage et de déverrouillage de session
    à partir du journal de sécurité de Windows pour tous les utilisateurs interactifs.

.DESCRIPTION
    Ce script utilise Get-WinEvent pour rechercher des ID d'événements spécifiques
    dans le journal de sécurité qui correspondent aux actions des utilisateurs
    telles que l'ouverture de session (4624), la fermeture de session (4634, 4647),
    le verrouillage (4800) et le déverrouillage (4801).
    Il filtre les événements pour ne montrer que les sessions interactives (locales ou RDP)
    et traduit les SID des utilisateurs en noms de compte lisibles.

.NOTES
    Auteur: Perplexity AI
    Date: 10 avril 2025
    Nécessite une exécution avec des privilèges d'administrateur pour accéder au journal de sécurité.
    L'audit des ouvertures/fermetures de session doit être activé dans la stratégie de sécurité locale
    (activé par défaut sur la plupart des systèmes Windows modernes).
#>
function Get-UserSessionActivity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [int]$Days = 7 # Nombre de jours passés à examiner par défaut
    )

    Write-Host "Recherche des événements de session des $Days derniers jours..." -ForegroundColor Yellow

    # Table de correspondance pour les ID d'événements et leur signification
    $eventMap = @{
        4624 = 'Ouverture de session (Logon)'      # Un compte a ouvert une session avec succès
        4634 = 'Fermeture de session (Logoff)'     # Une session a été fermée
        4647 = 'Fermeture de session initiée par l''utilisateur' # Logoff initié par l'utilisateur (souvent redondant avec 4634)
        4800 = 'Station verrouillée (Locked)'     # La station de travail a été verrouillée
        4801 = 'Station déverrouillée (Unlocked)' # La station de travail a été déverrouillée
    }
    $targetEventIDs = $eventMap.Keys

    # Types d'ouverture de session interactifs (2 = Local, 10 = RemoteInteractive/RDP)
    $interactiveLogonTypes = @(2, 10)

    # Définir la date de début pour la recherche
    $startTime = (Get-Date).AddDays(-$Days)

    # Construire le filtre pour Get-WinEvent (plus rapide que Get-EventLog)
    $filter = @{
        LogName   = 'Security'
        ID        = $targetEventIDs
        StartTime = $startTime
    }

    Write-Host "Interrogation du journal de sécurité pour les IDs : $($targetEventIDs -join ', ')..."

    # Récupérer les événements en utilisant le filtre
    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    } catch {
        Write-Error "Impossible de lire le journal de sécurité. Assurez-vous d'exécuter ce script en tant qu'administrateur et que l'audit est activé."
        return
    }

    Write-Host "$($events.Count) événements trouvés. Traitement en cours..."

    # Traiter chaque événement trouvé
    $sessionActivity = foreach ($event in $events) {
        $eventID = $event.Id
        $eventRecordID = $event.RecordId # Utile pour le débogage
        $eventTime = $event.TimeCreated

        # Extraire le SID de l'utilisateur et le type de logon si pertinent
        $userSid = $null
        $logonType = $null
        $userName = "N/A"

        try {
            # L'index des propriétés peut varier légèrement selon les versions de Windows/patchs
            switch ($eventID) {
                4624 { # Logon
                    # Propriété 8 contient généralement LogonType
                    $logonType = $event.Properties[8].Value
                    # Propriété 5 contient généralement le SID de l'utilisateur cible (TargetUserSid)
                    $userSid = New-Object System.Security.Principal.SecurityIdentifier($event.Properties[5].Value)
                }
                4634 { # Logoff
                    # Propriété 1 contient généralement TargetUserSid
                    $userSid = New-Object System.Security.Principal.SecurityIdentifier($event.Properties[1].Value)
                }
                 4647 { # User Initiated Logoff
                    # Propriété 1 contient généralement TargetUserSid
                    $userSid = New-Object System.Security.Principal.SecurityIdentifier($event.Properties[1].Value)
                }
                4800 { # Locked
                    # Propriété 1 contient généralement TargetUserName (pas SID ici)
                    $userName = $event.Properties[1].Value
                    # Essayer de récupérer le SID via la propriété 0 (TargetUserSid) si disponible
                    try { $userSid = New-Object System.Security.Principal.SecurityIdentifier($event.Properties[0].Value) } catch {}

                }
                4801 { # Unlocked
                     # Propriété 1 contient généralement TargetUserName (pas SID ici)
                    $userName = $event.Properties[1].Value
                     # Essayer de récupérer le SID via la propriété 0 (TargetUserSid) si disponible
                    try { $userSid = New-Object System.Security.Principal.SecurityIdentifier($event.Properties[0].Value) } catch {}
                }
            }

            # Filtrer pour ne garder que les logons interactifs (si ID = 4624)
            if ($eventID -eq 4624 -and $logonType -notin $interactiveLogonTypes) {
                continue # Passer à l'événement suivant si ce n'est pas un logon interactif
            }

            # Traduire le SID en nom d'utilisateur si disponible et userName n'est pas déjà défini
             if ($userSid -ne $null -and $userName -eq "N/A") {
                try {
                    $userName = $userSid.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $userName = $userSid.Value # Afficher le SID si la traduction échoue
                    Write-Warning "Impossible de traduire le SID $($userSid.Value) pour l'événement RecordID $eventRecordID."
                }
            }

            # Ignorer les comptes système communs si souhaité (décommentez la ligne ci-dessous pour activer)
            # if ($userName -in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE') -or $userName -like '*$') { continue }

            # Créer un objet de sortie personnalisé
            [PSCustomObject]@{
                Time      = $eventTime
                EventID   = $eventID
                EventType = $eventMap[$eventID]
                User      = $userName
                LogonType = if($logonType -ne $null) { $logonType } else { '-' } # Afficher le type de logon si applicable
                RecordID  = $eventRecordID # Pour référence
            }

        } catch {
            Write-Warning "Erreur lors du traitement de l'événement RecordID $eventRecordID : $($_.Exception.Message)"
        }
    }

    # Afficher les résultats triés par date/heure
    if ($sessionActivity) {
        Write-Host "Traitement terminé. Affichage des événements de session triés :" -ForegroundColor Green
        $sessionActivity | Sort-Object Time | Format-Table -AutoSize
    } else {
        Write-Host "Aucun événement de session pertinent trouvé pour la période spécifiée." -ForegroundColor Yellow
    }
}

# --- Exécution du script ---
# Exécute la fonction pour obtenir les événements des 7 derniers jours (par défaut)
# Vous pouvez spécifier un nombre de jours différent, ex: Get-UserSessionActivity -Days 30
Get-UserSessionActivity
