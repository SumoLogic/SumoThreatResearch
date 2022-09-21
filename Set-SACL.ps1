# Import the Set-AuditRule Script
. C:\Audit\Set-AuditRule.ps1

clear

<# All Sections follow the same basic logic:

- Find the location of the token - all effort is made to use environment variables here so that the paths are resolved dynamically, however, these tokens can be found in weird places if not installed using standard method, please double check all token locations

- If the token is found, get it's current SACL settings
- If the token does not have a SACL auditing setting (the script only looks for FileSystemRights auditing) then set one
- If the token does have a SACL set already, do nothing

To Do:

- Improve logic for finding cloud cred tokens
- Write output to a log file instead of Write-Host
- Add support for SSH Keys
- Put each token section in parameters, so you can do Set-SACLS.ps1 -Tokens Azure,Google OR Set-SACLS.ps1 -Tokens All 
- 

#>

<#

[Variable Names]

$AzureToken --> Full path of where the Azure token is, file name is "SessionTokens.json", this file is DPAPI encrypted
$AzureTokenACL --> The current ACL of SessionTokens.json
$AzureTokenACL.Audit.FileSystemRights --> The specific file auditing SACL entries for "SessionTokens.json"

$AWSCliPath --> The path to where the AWS CLI credentials are
$AWSCli --> The full path, including the file name of the "credentials" file where AWS CLI keys are stored, this file is in plain text
$AWSCLIACL --> The SACL entry for "credentials" 
$AWSCLIACL.Audit.FileSystemRights --> The specific file auditing SACL entries for "credentials"

$GCPAuthPath --> The path to where the Gcloud CLI credentials are, file is called credentials.db
$GCPAuthCreds --> The full path, including the file name of the "credentials.db" file where Gcloud CLI keys are stored
$GCPCLISACL --> The SACL entry for "credentials.db"
$GCPCLISACL.Audit.FileSystemRights --> The specific file audting SACL entries for "credentials.db"

$KubeConfigPath --> The path to where the kubeconfig file is, file is called "config"
$KubeConfig --> The full path, including the file name of the "config" kubeconfig file
$KubeConfigSACL --> The SACL entry for "config" 
$KubeConfigSACL.Audit.FileSystemRights --> The specific file auditing SACL entries for "KubeConfig"

[/Variable Names]

#>

# ---- Azure Token Section ------

# Get Location for the Azure Token
$AzureToken = Get-ChildItem -Path "$env:LOCALAPPDATA\.IdentityService" -Include "SessionTokens.json" -File -Recurse -ErrorAction SilentlyContinue 

# If the file exists, or, put another way, if the $AzureToken variable is populated with something 

if ($AzureToken) {

    if($AzureToken.Exists.ToString() = "True") { # If the file "SessionTokens.json" exists

        Write-Host "[*] Azure Token Found:" $AzureToken.FullName -ForegroundColor Magenta # Write to host that you found the token
        $AzureTokenACL = Get-Acl -Path $AzureToken.FullName -Audit # Get the current ACL, including the Audit settings, for the "SessionTokens.json" file
    
        if(!$AzureTokenACL.Audit.FileSystemRights) { # If there are no File System SACL auditing on the file

            Write-Host "[*] Azure Token Has no SACL, Setting One..." -ForegroundColor Yellow # Let user know that the file has no SACL on it
            Set-AuditRule -FilePath $AzureToken.FullName -WellKnownSidType WorldSid -Rights Read,Modify -InheritanceFlags None -PropagationFlags None -AuditFlags Failure,Success # Set the audit rule on the file
        
        }

        else {

                Write-Host "[*] Azure Token Already has SACL Applied..." -ForegroundColor Green # If the file already has a SACL, just let the user know and move on to the next token
        }

    }
}

else {

    Write-Host "[*] No Azure Token Found.."

}

# ---- End Azure Token Section ------

# ---- Azure CLI Token Section ------

# Get Location for the Azure Token
$AzureCLITokenPath = $env:HOMEDRIVE + $env:HOMEPATH + "\.azure"

$AzureCLIToken1 = Get-ChildItem -Path "$AzureCLITokenPath" -Include "msal_token_cache.bin" -File -Recurse -ErrorAction SilentlyContinue 
$AzureCLIToken2 = Get-ChildItem -Path "$AzureCLITokenPath" -Include "msal_http_cache.bin" -File -Recurse -ErrorAction SilentlyContinue 

# If the file exists, or, put another way, if the $AzureToken variable is populated with something 

if ($AzureCLIToken1) {

    if($AzureCLIToken1.Exists.ToString() = "True") { # If the file "msal_token_cache.bin" exists

        Write-Host "[*] Azure CLI Token Found:" $AzureCLIToken1.FullName -ForegroundColor Magenta # Write to host that you found the token
        $AzureCLIToken1ACL = Get-Acl -Path $AzureCLIToken1.FullName -Audit # Get the current ACL, including the Audit settings, for the "msal_token_cache" file
    
        if(!$AzureCLIToken1ACL.Audit.FileSystemRights) { # If there are no File System SACL auditing on the file

            Write-Host "[*] Azure CLI Token Has no SACL, Setting One..." -ForegroundColor Yellow # Let user know that the file has no SACL on it
            Set-AuditRule -FilePath $AzureCLIToken1.FullName -WellKnownSidType WorldSid -Rights Read,Modify -InheritanceFlags None -PropagationFlags None -AuditFlags Failure,Success # Set the audit rule on the file
        
        }

        else {

                Write-Host "[*] Azure CLI Token Already has SACL Applied..." -ForegroundColor Green # If the file already has a SACL, just let the user know and move on to the next token
        }

    }
}

else {

    Write-Host "[*] No Azure CLI Token Found.."

}

if ($AzureCLIToken2) {

    if($AzureCLIToken2.Exists.ToString() = "True") { # If the file "msal_http_cache.bin" exists

        Write-Host "[*] Azure CLI Token Found:" $AzureCLIToken2.FullName -ForegroundColor Magenta # Write to host that you found the token
        $AzureCLIToken2ACL = Get-Acl -Path $AzureCLIToken2.FullName -Audit # Get the current ACL, including the Audit settings, for the "msal_token_cache" file
    
        if(!$AzureCLIToken2ACL.Audit.FileSystemRights) { # If there are no File System SACL auditing on the file

            Write-Host "[*] Azure CLI Token Has no SACL, Setting One..." -ForegroundColor Yellow # Let user know that the file has no SACL on it
            Set-AuditRule -FilePath $AzureCLIToken2.FullName -WellKnownSidType WorldSid -Rights Read,Modify -InheritanceFlags None -PropagationFlags None -AuditFlags Failure,Success # Set the audit rule on the file
        
        }

        else {

                Write-Host "[*] Azure CLI Token Already has SACL Applied..." -ForegroundColor Green # If the file already has a SACL, just let the user know and move on to the next token
        }

    }
}

else {

    Write-Host "[*] No Azure CLI Token Found.."

}

# ---- End Azure CLI Token Section ------


# ---- AWS CLI Token Section ------

# Exact same logic as the Azure token section, just building the path a little differently here to avoid hard-coded paths

$AWSCliPath = $env:HOMEDRIVE + $env:HOMEPATH + "\.aws"
$AWSCli = Get-ChildItem -Path $AWSCliPath -Include "credentials" -File -Recurse -ErrorAction SilentlyContinue

if ($AWSCli) {


    if($AWSCli.Exists.ToString() = "True") {

        Write-Host "[*] AWS CLI Credentials Found:" $AWSCli.FullName -ForegroundColor Magenta
        $AWSCLIACL = Get-Acl -Path $AWSCli.FullName -Audit
        if(!$AWSCLIACL.Audit.FileSystemRights) {

            Write-Host "[*] AWS CLI Credentials have no SACL, Setting One.." -ForegroundColor Yellow
            Set-AuditRule -FilePath $AWSCli.FullName -WellKnownSidType WorldSid -Rights Read,Modify -InheritanceFlags None -PropagationFlags None -AuditFlags Failure,Success
        }

        else {

            Write-Host "[*] AWS CLI Credentials Already Have SACL Applied" -ForegroundColor Green

        }
        
    }

}

else {

    Write-Host "[*] No AWS CLI File Found ..."
}

# ---- END AWS CLI Token Section ------

# ---- Google Cloud Token Section ------

# Exact same logic as the Azure token section, just building the path a little differently here, like the AWS token, to avoid hard-coded paths

$GCPAuthPath = $env:APPDATA + "\gcloud"
$GCPAuthCreds = Get-ChildItem -Path $GCPAuthPath -Include "credentials.db" -File -Recurse -ErrorAction SilentlyContinue

if($GCPAuthCreds) {

    if($GCPAuthCreds.Exists.ToString() = "True") {

        Write-Host "[*] GCP CLI Credentials Found:" $GCPAuthCreds.FullName -ForegroundColor Magenta
        $GCPCLISACL = Get-Acl -Path $GCPAuthCreds.FullName -Audit

        if(!$GCPCLISACL.Audit.FileSystemRights) {

            Write-Host "[*] GCP CLI Credentials Have no SACL, Setting One.." -ForegroundColor Yellow
            Set-AuditRule -FilePath $GCPAuthCreds.FullName -WellKnownSidType WorldSid -Rights Read,Modify -InheritanceFlags None -PropagationFlags None -AuditFlags Failure,Success

        }

        else {

            Write-Host "[*] GCP CLI Credentials Have SACL Applied" -ForegroundColor Green
        
        }
        
    }

}

else {

    Write-Host "[*] No GCP Credentials Found... "

}

# ---- End Google Cloud Token Section ------

# ---- Kubectl Token Section ------

# Exact same logic as the Azure token section, just building the path a little differently here to avoid hard-coded paths

$KubeConfigPath = $env:USERPROFILE + "\.kube"
$KubeConfig =  Get-ChildItem -Path $KubeConfigPath -Include "config" -File -Recurse -ErrorAction SilentlyContinue

if($KubeConfig) {

    if($KubeConfig.Exists.ToString() = "True") {

        Write-Host "[*] Kubeconfig Found" $KubeConfig.FullName -ForegroundColor Magenta
        $KubeConfigSACL = Get-Acl -Path $KubeConfig.FullName -Audit

        if(!$KubeConfigSACL.Audit.FileSystemRights) {

            Write-Host "[*] Kube Config Has no SACL, Setting One.." -ForegroundColor Yellow
            Set-AuditRule -FilePath $KubeConfig.FullName -WellKnownSidType WorldSid -Rights Read,Modify -InheritanceFlags None -PropagationFlags None -AuditFlags Failure,Success
        }

        else {

            Write-Host "[*] Kubeconfig Already has SACL applied" -ForegroundColor Green

        }
        
    }

}

else {

    Write-Host "[*] No KubeConfig File Found... "
}

# ---- End Kubectl Section ------

Write-Host "[*] All done, happy hunting" -ForegroundColor DarkYellow