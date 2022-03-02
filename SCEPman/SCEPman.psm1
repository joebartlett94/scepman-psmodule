# for testing
#$env:SCEPMAN_APP_SERVICE_NAME = "as-scepman-deploytest"
#$env:CERTMASTER_APP_SERVICE_NAME = "aleen-as-certmaster-askjvljweklraesr"
#$env:SCEPMAN_RESOURCE_GROUP = "rg-SCEPman" # Optional

$SCEPmanAppServiceName = $env:SCEPMAN_APP_SERVICE_NAME
$CertMasterAppServiceName = $env:CERTMASTER_APP_SERVICE_NAME
$SCEPmanResourceGroup = $env:SCEPMAN_RESOURCE_GROUP
$SubscriptionId = $env:SUBSCRIPTION_ID

# Some hard-coded definitions
$MSGraphAppId = "00000003-0000-0000-c000-000000000000"
$MSGraphDirectoryReadAllPermission = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
$MSGraphDeviceManagementReadPermission = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
$MSGraphUserReadPermission = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"

# "0000000a-0000-0000-c000-000000000000" # Service Principal App Id of Intune, not required here
$IntuneAppId = "c161e42e-d4df-4a3d-9b42-e7a3c31f59d4" # Well-known App ID of the Intune API
$IntuneSCEPChallengePermission = "39d724e8-6a34-4930-9a36-364082c35716"

$MAX_RETRY_COUNT = 4  # for some operations, retry a couple of times

$azureADAppNameForSCEPman = 'SCEPman-api' #Azure AD app name for SCEPman
$azureADAppNameForCertMaster = 'SCEPman-CertMaster' #Azure AD app name for certmaster

# JSON defining App Role that CertMaster uses to authenticate against SCEPman
$ScepmanManifest = '[{
        \"allowedMemberTypes\": [
          \"Application\"
        ],
        \"description\": \"Request certificates via the raw CSR API\",
        \"displayName\": \"CSR Requesters\",
        \"isEnabled\": \"true\",
        \"value\": \"CSR.Request\"
    }]'.Replace("`r", [String]::Empty).Replace("`n", [String]::Empty)

# JSON defining App Role that User can have to when authenticating against CertMaster
$CertmasterManifest = '[{
    \"allowedMemberTypes\": [
      \"User\"
    ],
    \"description\": \"Full access to all SCEPman CertMaster functions like requesting and managing certificates\",
    \"displayName\": \"Full Admin\",
    \"isEnabled\": \"true\",
    \"value\": \"Admin.Full\"
}]'.Replace("`r", [String]::Empty).Replace("`n", [String]::Empty)


function ConvertLinesToObject($lines) {
    if($null -eq $lines) {
        return $null
    }
    $linesJson = [System.String]::Concat($lines)
    return ConvertFrom-Json $linesJson
}

function AzLogin {
        # Check whether az is available
    $azCommand = Get-Command az 2>&1
    if ($azCommand.GetType() -eq [System.Management.Automation.ErrorRecord]) {
        if ($azCommand.CategoryInfo.Reason -eq "CommandNotFoundException") {
            $errorMessage = "Azure CLI (az) is not installed, but required. Please use the Azure Cloud Shell or install Azure CLI as described here: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
            Write-Error $errorMessage
            throw $errorMessage
        }
        else {
            Write-Error "Unknown error checking for az"
            throw $azCommand
        }
    }

        # check whether already logged in
    $account = az account show 2>&1
    if ($account.GetType() -eq [System.Management.Automation.ErrorRecord]) {
        if ($account.ToString().Contains("az login")) {
            Write-Host "Not logged in to az yet. Please log in."
            $null = az login # TODO: Check whether the login worked
        }
        else {
            Write-Error "Error $account while trying to use az" # possibly az not installed?
            throw $account
        }
    } else {
        $accountInfo = ConvertLinesToObject($account)
        Write-Output "Logged in to az as $($accountInfo.user.name)"
    }
}

function GetSubscriptionDetailsUsingSCEPmanAppName($subscriptions) {
    $correctSubscription = $null
    Write-Output "Finding correct subscription"
    $scWebAppsAcrossAllAccessibleSubscriptions = ConvertLinesToObject -lines $(az graph query -q "Resources | where type == 'microsoft.web/sites' and name == '$SCEPmanAppServiceName' | project name, subscriptionId" -s $subscriptions.id)
    if($scWebAppsAcrossAllAccessibleSubscriptions.count -eq 1) {
        $correctSubscription = $subscriptions | Where-Object { $_.id -eq $scWebAppsAcrossAllAccessibleSubscriptions.data[0].subscriptionId }
    }
    if($null -eq $correctSubscription) {
        $errorMessage = "We are unable to determine the correct subscription. Please start over"
        Write-Error $errorMessage
        throw $errorMessage
    }
    return $correctSubscription
}

function GetSubscriptionDetails {
  $potentialSubscription = $null
  $subscriptions = ConvertLinesToObject -lines $(az account list)
  if($false -eq [String]::IsNullOrWhiteSpace($SubscriptionId)) {
    $potentialSubscription = $subscriptions | Where-Object { $_.id -eq $SubscriptionId }
    if($null -eq $potentialSubscription) {
        Write-Warning "We are unable to find the subscription with id $SubscriptionId"
        throw "We are unable to find the subscription with id $SubscriptionId"
    }
  }
  if($null -eq $potentialSubscription) {
    if($subscriptions.count -gt 1){
        Write-Host "Multiple subscriptions found! Select a subscription where the SCPEman is installed or press '0' to search across all of the subscriptions"
        Write-Host "0: Search All Subscriptions | Press '0'"
        for($i = 0; $i -lt $subscriptions.count; $i++){
            Write-Host "$($i + 1): $($subscriptions[$i].name) | Subscription Id: $($subscriptions[$i].id) | Press '$($i + 1)' to use this subscription"
        }
        $selection = Read-Host -Prompt "Please enter your choice and hit enter"
        if(0 -eq $selection) {
            $potentialSubscription = GetSubscriptionDetailsUsingSCEPmanAppName -subscriptions $subscriptions
        } else {
            $potentialSubscription = $subscriptions[$($selection - 1)]
        }
        if($null -eq $potentialSubscription) {
            Write-Error "We couldn't find the selected subscription. Please try to re-run the script"
            throw "We couldn't find the selected subscription. Please try to re-run the script"
        }
      } else {
        $potentialSubscription = $subscriptions[0]
      }
  }
  $null = az account set --subscription $($potentialSubscription.id)
  return $potentialSubscription
}

# It is intended to use for az cli add permissions and az cli add permissions admin
# $azCommand - The command to execute.
#
function ExecuteAzCommandRobustly($azCommand, $principalId = $null, $appRoleId = $null) {
  $azErrorCode = 1234 # A number not null
  $retryCount = 0
  while ($azErrorCode -ne 0 -and $retryCount -le $MAX_RETRY_COUNT) {
    $lastAzOutput = Invoke-Expression $azCommand 2>&1 # the output is often empty in case of error :-(. az just writes to the console then
    $azErrorCode = $LastExitCode
    if ($null -ne $lastAzOutput -and $lastAzOutput.GetType() -eq [System.Management.Automation.ErrorRecord]) {
        if ($lastAzOutput.ToString().Contains("Permission being assigned already exists on the object")) {  # TODO: Does this work in non-English environments?
            Write-Output "Permission is already assigned when executing $azCommand"
            $azErrorCode = 0
        } else {
            if (0 -eq $azErrorCode) {
                $azErrorCode = 666 # A number not 0 to enforce another iteration of the loop and retry
            }
        }
    } else {
        if($null -ne $appRoleId -and $azErrorCode -eq 0) {
            $appRoleAssignments = ConvertLinesToObject -lines $(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments")
            $grantedPermission = $appRoleAssignments.value | Where-Object { $_.appRoleId -eq $appRoleId }
            if ($null -eq $grantedPermission) {
                $azErrorCode = 999 # A number not 0
            }
        }
    }
    if ($azErrorCode -ne 0) {
      ++$retryCount
      Write-Verbose "Retry $retryCount for $azCommand"
      Start-Sleep $retryCount # Sleep for some seconds, as the grant sometimes only works after some time
    }
  }
  if ($azErrorCode -ne 0 ) {
    Write-Error "Error $azErrorCode when executing $azCommand : $($lastAzOutput.ToString())"
    throw "Error $azErrorCode when executing $azCommand : $($lastAzOutput.ToString())"
  }
  else {
    return $lastAzOutput
  }
}

function GetResourceGroup {
  if ([String]::IsNullOrWhiteSpace($SCEPmanResourceGroup)) {
    # No resource group given, search for it now
    $scWebAppsInTheSubscription = ConvertLinesToObject -lines $(az graph query -q "Resources | where type == 'microsoft.web/sites' and name == '$SCEPmanAppServiceName' | project name, resourceGroup")
    if($null -ne $scWebAppsInTheSubscription -and $($scWebAppsInTheSubscription.count) -eq 1) {
        return $scWebAppsInTheSubscription.data[0].resourceGroup
    }
    Write-Error "Unable to determine the resource group. This generally happens when a wrong name is entered for the SCEPman web app!"
    throw "Unable to determine the resource group. This generally happens when a wrong name is entered for the SCEPman web app!"
  }
  return $SCEPmanResourceGroup;
}


function GetCertMasterAppServiceName {
    if ([String]::IsNullOrWhiteSpace($CertMasterAppServiceName)) {

    #       Criteria:
    #       - Only two App Services in SCEPman's resource group. One is SCEPman, the other the CertMaster candidate
    #       - Configuration value AppConfig:SCEPman:URL must be present, then it must be a CertMaster
    #       - In a default installation, the URL must contain SCEPman's app service name. We require this.

      $rgwebapps =  ConvertLinesToObject -lines $(az graph query -q "Resources | where type == 'microsoft.web/sites' and resourceGroup == '$SCEPmanResourceGroup' and name !~ '$SCEPmanAppServiceName' | project name")
      Write-Output "$($rgwebapps.count + 1) web apps found in the resource group $SCEPmanResourceGroup. We are finding if the CertMaster app is already created"
      if($rgwebapps.count -gt 0) {
        ForEach($potentialcmwebapp in $rgwebapps.data) {
            $scepmanurlsettingcount = az webapp config appsettings list --name $potentialcmwebapp.name --resource-group $SCEPmanResourceGroup --query "[?name=='AppConfig:SCEPman:URL'].value | length(@)"
            if($scepmanurlsettingcount -eq 1) {
                $scepmanUrl = az webapp config appsettings list --name $potentialcmwebapp.name --resource-group $SCEPmanResourceGroup --query "[?name=='AppConfig:SCEPman:URL'].value | [0]"
                $hascorrectscepmanurl = $scepmanUrl.ToUpperInvariant().Contains($SCEPmanAppServiceName.ToUpperInvariant())
                if($hascorrectscepmanurl -eq $true) {
                    Write-Output "CertMaster web app $($potentialcmwebapp.name) found."
                    $CertMasterAppServiceName = $potentialcmwebapp.name
                    return $potentialcmwebapp.name
                }
            }
        }
      }
      Write-Warning "Unable to determine the Certmaster app service name"
      return $null
    }
    return $CertMasterAppServiceName;
}

function CreateCertMasterAppService {
  $CertMasterAppServiceName = GetCertMasterAppServiceName
  $CreateCertMasterAppService = $false

  if($null -eq $CertMasterAppServiceName) {
    $CreateCertMasterAppService =  $true
  } else {
    # This can happen if user uses environment variable to set the CertMaster app service name
    $CertMasterWebApps = ConvertLinesToObject -lines $(az graph query -q "Resources | where type == 'microsoft.web/sites' and resourceGroup == '$SCEPmanResourceGroup' and name =~ '$CertMasterAppServiceName' | project name")
    if(0 -eq $CertMasterWebApps.count) {
        $CreateCertMasterAppService =  $true
    }
  }

  $scwebapp = ConvertLinesToObject -lines $(az graph query -q "Resources | where type == 'microsoft.web/sites' and resourceGroup == '$SCEPmanResourceGroup' and name =~ '$SCEPmanAppServiceName'")

  if($null -eq $CertMasterAppServiceName) {
    $CertMasterAppServiceName = $scwebapp.data.name
    if ($CertMasterAppServiceName.Length -gt 57) {
      $CertMasterAppServiceName = $CertMasterAppServiceName.Substring(0,57)
    }

    $CertMasterAppServiceName += "-cm"
    $potentialCertMasterAppServiceName = Read-Host "CertMaster web app not found. Please hit enter now if you want to create the app with name $CertMasterAppServiceName or enter the name of your choice, and then hit enter"

    if($potentialCertMasterAppServiceName) {
        $CertMasterAppServiceName = $potentialCertMasterAppServiceName
    }
  }

  if ($true -eq $CreateCertMasterAppService) {

    Write-Output "User selected to create the app with the name $CertMasterAppServiceName"

    $null = az webapp create --resource-group $SCEPmanResourceGroup --plan $scwebapp.data.properties.serverFarmId --name $CertMasterAppServiceName --assign-identity [system] --% --runtime "DOTNET|5.0"
    Write-Output "CertMaster web app $CertMasterAppServiceName created"

    # Do all the configuration that the ARM template does normally
    $CertmasterAppSettings = @{
      WEBSITE_RUN_FROM_PACKAGE = "https://raw.githubusercontent.com/scepman/install/master/dist-certmaster/CertMaster-Artifacts.zip";
      "AppConfig:AuthConfig:TenantId" = $subscription.tenantId;
      "AppConfig:SCEPman:URL" = "https://$($scwebapp.data.properties.defaultHostName)/";
    } | ConvertTo-Json -Compress
    $CertMasterAppSettings = $CertmasterAppSettings.Replace('"', '\"')

    Write-Verbose 'Configuring CertMaster web app settings'
    $null = az webapp config set --name $CertMasterAppServiceName --resource-group $SCEPmanResourceGroup --use-32bit-worker-process $false --ftps-state 'Disabled' --always-on $true
    $null = az webapp update --name $CertMasterAppServiceName --resource-group $SCEPmanResourceGroup --https-only $true
    $null = az webapp config appsettings set --name $CertMasterAppServiceName --resource-group $SCEPmanResourceGroup --settings $CertMasterAppSettings
  }

  return $CertMasterAppServiceName
}

function GetStorageAccount {
    $storageaccounts = ConvertLinesToObject -lines $(az graph query -q "Resources | where type == 'microsoft.storage/storageaccounts' and resourceGroup == '$SCEPmanResourceGroup' | project name, primaryEndpoints = properties.primaryEndpoints")
    if($storageaccounts.count -gt 0) {
        $potentialStorageAccountName = Read-Host "We have found one or more existing storage accounts in the resource group $SCEPmanResourceGroup. Please hit enter now if you still want to create a new storage account or enter the name of the storage account you would like to use, and then hit enter"
        if(!$potentialStorageAccountName) {
            Write-Output "User selected to create a new storage account"
            return $null
        } else {
            $potentialStorageAccount = $storageaccounts.data | Where-Object { $_.name -eq $potentialStorageAccountName }
            if($null -eq $potentialStorageAccount) {
                Write-Error "We couldn't find a storage account with name $potentialStorageAccountName. Please try to re-run the script"
                throw "We couldn't find a storage account with name $potentialStorageAccountName. Please try to re-run the script"
            } else {
                return $potentialStorageAccount
            }
        }
    }
    else {
        Write-Warning "Unable to determine the storage account"
        return $null
    }
}


function CreateScStorageAccount {
    $ScStorageAccount = GetStorageAccount
    if($null -eq $ScStorageAccount) {
        Write-Output 'Storage account not found. We will create one now'
        $storageAccountName = $SCEPmanResourceGroup.ToLower() -replace '[^a-z0-9]',''
        if($storageAccountName.Length -gt 19) {
            $storageAccountName = $storageAccountName.Substring(0,19)
        }
        $storageAccountName = "stg$($storageAccountName)cm"
        $potentialStorageAccountName = Read-Host "Please hit enter now if you want to create the storage account with name $storageAccountName or enter the name of your choice, and then hit enter"
        if($potentialStorageAccountName) {
            $storageAccountName = $potentialStorageAccountName
        }
        $ScStorageAccount = ConvertLinesToObject -lines $(az storage account create --name $storageAccountName --resource-group $SCEPmanResourceGroup --sku 'Standard_LRS' --kind 'StorageV2' --access-tier 'Hot' --allow-blob-public-access $true --allow-cross-tenant-replication $false --allow-shared-key-access $false --enable-nfs-v3 $false --min-tls-version 'TLS1_2' --publish-internet-endpoints $false --publish-microsoft-endpoints $false --routing-choice 'MicrosoftRouting' --https-only $true --only-show-errors)
        if($null -eq $ScStorageAccount) {
            Write-Error 'Storage account not found and we are unable to create one. Please check logs for more details before re-running the script'
            throw 'Storage account not found and we are unable to create one. Please check logs for more details before re-running the script'
        }
        Write-Output "Storage account $storageAccountName created"
    }
    Write-Output "Setting permissions in storage account for SCEPman, SCEPman's deployment slots (if any), and CertMaster"
    $null = az role assignment create --role 'Storage Table Data Contributor' --assignee-object-id $serviceprincipalcm.principalId --assignee-principal-type 'ServicePrincipal' --scope "/subscriptions/$($subscription.id)/resourceGroups/$SCEPmanResourceGroup/providers/Microsoft.Storage/storageAccounts/$($ScStorageAccount.name)"
    $null = az role assignment create --role 'Storage Table Data Contributor' --assignee-object-id $serviceprincipalsc.principalId --assignee-principal-type 'ServicePrincipal' --scope "/subscriptions/$($subscription.id)/resourceGroups/$SCEPmanResourceGroup/providers/Microsoft.Storage/storageAccounts/$($ScStorageAccount.name)"
    if($true -eq $scHasDeploymentSlots) {
        ForEach($tempServicePrincipal in $serviceprincipalOfScDeploymentSlots) {
            $null = az role assignment create --role 'Storage Table Data Contributor' --assignee-object-id $tempServicePrincipal.principalId --assignee-principal-type 'ServicePrincipal' --scope "/subscriptions/$($subscription.id)/resourceGroups/$SCEPmanResourceGroup/providers/Microsoft.Storage/storageAccounts/$($ScStorageAccount.name)"
        }
    }
    return $ScStorageAccount
}

function SetTableStorageEndpointsInScAndCmAppSettings {

    $existingTableStorageEndpointSettingSc = az webapp config appsettings list --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --query "[?name=='AppConfig:CertificateStorage:TableStorageEndpoint'].value | [0]"
    $existingTableStorageEndpointSettingCm = az webapp config appsettings list --name $CertMasterAppServiceName --resource-group $SCEPmanResourceGroup --query "[?name=='AppConfig:AzureStorage:TableStorageEndpoint'].value | [0]"
    $storageAccountTableEndpoint = $null

    if(![string]::IsNullOrEmpty($existingTableStorageEndpointSettingSc)) {
        if(![string]::IsNullOrEmpty($existingTableStorageEndpointSettingCm) -and $existingTableStorageEndpointSettingSc -ne $existingTableStorageEndpointSettingCm) {
            Write-Error "Inconsistency: SCEPman($SCEPmanAppServiceName) and CertMaster($CertMasterAppServiceName) have different storage accounts configured"
            throw "Inconsistency: SCEPman($SCEPmanAppServiceName) and CertMaster($CertMasterAppServiceName) have different storage accounts configured"
        }
        $storageAccountTableEndpoint = $existingTableStorageEndpointSettingSc
    }

    if([string]::IsNullOrEmpty($storageAccountTableEndpoint) -and ![string]::IsNullOrEmpty($existingTableStorageEndpointSettingCm)) {
        $storageAccountTableEndpoint = $existingTableStorageEndpointSettingCm
    }

    if([string]::IsNullOrEmpty($storageAccountTableEndpoint)) {
        Write-Output "Getting storage account"
        $ScStorageAccount = CreateScStorageAccount
        $storageAccountTableEndpoint = $($ScStorageAccount.primaryEndpoints.table)
    } else {
        Write-Verbose 'Storage account table endpoint found in app settings'
    }

    #TODO: Grant permissions to the existing storage accounts

    Write-Verbose "Configuring table storage endpoints in SCEPman, SCEPman's deployment slots (if any), and CertMaster"
    $null = az webapp config appsettings set --name $CertMasterAppServiceName --resource-group $SCEPmanResourceGroup --settings AppConfig:AzureStorage:TableStorageEndpoint=$storageAccountTableEndpoint
    $null = az webapp config appsettings set --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --settings AppConfig:CertificateStorage:TableStorageEndpoint=$storageAccountTableEndpoint
    if($true -eq $scHasDeploymentSlots) {
        ForEach($tempDeploymentSlot in $deploymentSlotsSc) {
            $null = az webapp config appsettings set --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --settings AppConfig:CertificateStorage:TableStorageEndpoint=$script:storageAccountTableEndpoint --slot $tempDeploymentSlot
        }
    }
}

function GetDeploymentSlots($appServiceNameParam, $resourceGroupParam) {
    $deploymentSlots = ConvertLinesToObject -lines $(az webapp deployment slot list --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --query '[].name')
    return $deploymentSlots
}

function GetServicePrincipal($appServiceNameParam, $resourceGroupParam, $slotNameParam = $null) {
    $identityShowParams = "";
    if($null -ne $slotNameParam) {
        $identityShowParams = "--slot", $slotNameParam
    }
    return ConvertLinesToObject -lines $(az webapp identity show --name $appServiceNameParam --resource-group $resourceGroupParam @identityShowParams)
}

function GetAzureResourceAppId($appId) {
    return $(az ad sp list --filter "appId eq '$appId'" --query [0].objectId --out tsv)
}

function SetManagedIdentityPermissions($principalId, $resourcePermissions) {
    $graphEndpointForAppRoleAssignments = "https://graph.microsoft.com/v1.0/servicePrincipals/$($principalId)/appRoleAssignments"
    $alreadyAssignedPermissions = ExecuteAzCommandRobustly -azCommand "az rest --method get --uri '$graphEndpointForAppRoleAssignments' --headers 'Content-Type=application/json' --query 'value[].appRoleId' --output tsv"

    ForEach($resourcePermission in $resourcePermissions) {
        if(($alreadyAssignedPermissions -contains $resourcePermission.appRoleId) -eq $false) {
            $bodyToAddPermission = "{'principalId': '$($principalId)','resourceId': '$($resourcePermission.resourceId)','appRoleId':'$($resourcePermission.appRoleId)'}"
            $null = ExecuteAzCommandRobustly -azCommand "az rest --method post --uri '$graphEndpointForAppRoleAssignments' --body `"$bodyToAddPermission`" --headers 'Content-Type=application/json'" -principalId $principalId -appRoleId $resourcePermission.appRoleId
        }
    }
}


function GetAzureADApp($name) {
    return ConvertLinesToObject -lines $(az ad app list --filter "displayname eq '$name'" --query "[0]")
}

function CreateServicePrincipal($appId) {
    $sp = ConvertLinesToObject -lines $(az ad sp list --filter "appId eq '$appId'" --query "[0]")
    if($null -eq $sp) {
        #App Registration SP doesn't exist.
        return ConvertLinesToObject -lines $(ExecuteAzCommandRobustly -azCommand "az ad sp create --id $appId")
    }
    else {
        return $sp
    }
}

function RegisterAzureADApp($name, $manifest, $replyUrls = $null) {
    $azureAdAppReg = ConvertLinesToObject -lines $(az ad app list --filter "displayname eq '$name'" --query "[0]")
    if($null -eq $azureAdAppReg) {
        #App Registration doesn't exist.
        if($null -eq $replyUrls) {
            $azureAdAppReg = ConvertLinesToObject -lines $(ExecuteAzCommandRobustly -azCommand "az ad app create --display-name '$name' --app-roles '$manifest'")
        }
        else {
            $azureAdAppReg = ConvertLinesToObject -lines $(ExecuteAzCommandRobustly -azCommand "az ad app create --display-name '$name' --app-roles '$manifest' --reply-urls '$replyUrls'")
        }
    }
    return $azureAdAppReg
}

function AddDelegatedPermissionToCertMasterApp($appId) {
    $certMasterPermissions = ConvertLinesToObject -lines $(az ad app permission list --id $appId --query "[0]")
    if($null -eq ($certMasterPermissions.resourceAccess | Where-Object { $_.id -eq $MSGraphUserReadPermission })) {
        $null = ExecuteAzCommandRobustly -azCommand "az ad app permission add --id $appId --api $MSGraphAppId --api-permissions `"$MSGraphUserReadPermission=Scope`" --only-show-errors"
    }
    $certMasterPermissionsGrantsString = ConvertLinesToObject -lines $(az ad app permission list-grants --id $appId --query "[0].scope")
    $requiresPermissionGrant = $false
    if ($null -eq $certMasterPermissionsGrantsString) {
        $requiresPermissionGrant = $true
    } else {
        $certMasterPermissionsGrants = $certMasterPermissionsGrantsString.ToString().Split(" ")
        if(($certMasterPermissionsGrants -contains "User.Read") -eq $false) {
            $requiresPermissionGrant = $true
        }
    }
    if($true -eq $requiresPermissionGrant) {
        $null = ExecuteAzCommandRobustly -azCommand "az ad app permission grant --id $appId --api $MSGraphAppId --scope `"User.Read`" --expires `"never`""
    }
}

<#
 .Synopsis
  Adds the required configuration to SCEPman (https://scepman.com/) right after installing or updating to a 2.x version.

 .Parameter SCEPmanAppServiceName
  The name of the SCEPman App Service

 .Parameter CertMasterAppServiceName
  The name of the SCEPman Certificate Master App Service

 .Parameter SCEPmanResourceGroup
  The Azure resource group hosting the SCEPman App Service

 .Example
   # Configure SCEPman in your tenant where the app service name is as-scepman
   Configure-SCEPman -SCEPmanAppServiceName as-scepman

 .Example
   # Configure SCEPman and ask interactively for the app service
   Configure-SCEPman
#>
function Complete-SCEPmanInstallation($SCEPmanAppServiceName, $CertMasterAppServiceName, $SCEPmanResourceGroup)
{
    if ([String]::IsNullOrWhiteSpace($SCEPmanAppServiceName)) {
    $SCEPmanAppServiceName = Read-Host "Please enter the SCEPman app service name"
    }

    Write-Output "Installing az resource graph extension"
    az extension add --name resource-graph --only-show-errors

    Write-Output "Configuring SCEPman and CertMaster"

    Write-Output "Logging in to az"
    AzLogin

    Write-Output "Getting subscription details"
    $subscription = GetSubscriptionDetails
    Write-Output "Subscription is set to $($subscription.name)"

    Write-Output "Setting resource group"
    $SCEPmanResourceGroup = GetResourceGroup

    Write-Output "Getting SCEPman deployment slots"
    $scHasDeploymentSlots = $false
    $deploymentSlotsSc = GetDeploymentSlots -appServiceNameParam $SCEPmanAppServiceName -resourceGroupParam $SCEPmanResourceGroup
    if($null -ne $deploymentSlotsSc -and $deploymentSlotsSc.Count -gt 0) {
        $scHasDeploymentSlots = $true
        Write-Output "$($deploymentSlotsSc.Count) found"
    } else {
        Write-Output "No deployment slots found"
    }


    Write-Output "Getting CertMaster web app"
    $CertMasterAppServiceName = CreateCertMasterAppService

    # Service principal of System-assigned identity of SCEPman
    $serviceprincipalsc = GetServicePrincipal -appServiceNameParam $SCEPmanAppServiceName -resourceGroupParam $SCEPmanResourceGroup

    # Service principal of System-assigned identity of CertMaster
    $serviceprincipalcm = GetServicePrincipal -appServiceNameParam $CertMasterAppServiceName -resourceGroupParam $SCEPmanResourceGroup

    $serviceprincipalOfScDeploymentSlots = @()

    if($true -eq $scHasDeploymentSlots) {
        ForEach($deploymentSlot in $deploymentSlotsSc) {
            $tempDeploymentSlot = GetServicePrincipal -appServiceNameParam $SCEPmanAppServiceName -resourceGroupParam $SCEPmanResourceGroup -slotNameParam $deploymentSlot
            if($null -eq $tempDeploymentSlot) {
                Write-Error "Deployment slot '$deploymentSlot' doesn't have managed identity turned on"
                throw "Deployment slot '$deploymentSlot' doesn't have managed identity turned on"
            }
            $serviceprincipalOfScDeploymentSlots += $tempDeploymentSlot
        }
    }

    SetTableStorageEndpointsInScAndCmAppSettings

    $CertMasterBaseURL = "https://$CertMasterAppServiceName.azurewebsites.net"
    Write-Verbose "CertMaster web app url is $CertMasterBaseURL"

    $graphResourceId = GetAzureResourceAppId -appId $MSGraphAppId
    $intuneResourceId = GetAzureResourceAppId -appId $IntuneAppId


    ### Set managed identity permissions for SCEPman
    $resourcePermissionsForSCEPman =
        @([pscustomobject]@{'resourceId'=$graphResourceId;'appRoleId'=$MSGraphDirectoryReadAllPermission;},
        [pscustomobject]@{'resourceId'=$graphResourceId;'appRoleId'=$MSGraphDeviceManagementReadPermission;},
        [pscustomobject]@{'resourceId'=$intuneResourceId;'appRoleId'=$IntuneSCEPChallengePermission;}
    )
    Write-Output "Setting up permissions for SCEPman"
    SetManagedIdentityPermissions -principalId $serviceprincipalsc.principalId -resourcePermissions $resourcePermissionsForSCEPman

    if($true -eq $scHasDeploymentSlots) {
        Write-Output "Setting up permissions for SCEPman deployment slots"
        ForEach($tempServicePrincipal in $serviceprincipalOfScDeploymentSlots) {
            SetManagedIdentityPermissions -principalId $tempServicePrincipal.principalId -resourcePermissions $resourcePermissionsForSCEPman
        }
    }

    Write-Output "Creating Azure AD app registration for SCEPman"
    ### SCEPman App Registration
    # Register SCEPman App
    $appregsc = RegisterAzureADApp -name $azureADAppNameForSCEPman -manifest $ScepmanManifest
    $spsc = CreateServicePrincipal -appId $($appregsc.appId)

    $ScepManSubmitCSRPermission = $appregsc.appRoles[0].id

    # Expose SCEPman API
    ExecuteAzCommandRobustly -azCommand "az ad app update --id $($appregsc.appId) --identifier-uris `"api://$($appregsc.appId)`""

    Write-Output "Allowing CertMaster to submit CSR requests to SCEPman API"
    # Allow CertMaster to submit CSR requests to SCEPman API
    $resourcePermissionsForCertMaster = @([pscustomobject]@{'resourceId'=$($spsc.objectId);'appRoleId'=$ScepManSubmitCSRPermission;})
    SetManagedIdentityPermissions -principalId $serviceprincipalcm.principalId -resourcePermissions $resourcePermissionsForCertMaster


    Write-Output "Creating Azure AD app registration for CertMaster"
    ### CertMaster App Registration

    # Register CertMaster App
    $appregcm = RegisterAzureADApp -name $azureADAppNameForCertMaster -manifest $CertmasterManifest -replyUrls `"$CertMasterBaseURL/signin-oidc`"
    $null = CreateServicePrincipal -appId $($appregcm.appId)

    # Add Microsoft Graph's User.Read as delegated permission for CertMaster
    AddDelegatedPermissionToCertMasterApp -appId $appregcm.appId


    Write-Output "Configuring SCEPman, SCEPman's deployment slots (if any), and CertMaster web app settings"

    # Add ApplicationId and some additional defaults in SCEPman web app settings
    $ScepManAppSettings = "{\`"AppConfig:AuthConfig:ApplicationId\`":\`"$($appregsc.appId)\`",\`"AppConfig:CertMaster:URL\`":\`"$($CertMasterBaseURL)\`",\`"AppConfig:DirectCSRValidation:Enabled\`":\`"true\`",\`"AppConfig:AuthConfig:UseManagedIdentity\`":\`"true\`"}".Replace("`r", [String]::Empty).Replace("`n", [String]::Empty)
    $null = az webapp config appsettings set --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --settings $ScepManAppSettings

    if($true -eq $scHasDeploymentSlots) {
        ForEach($tempDeploymentSlot in $deploymentSlotsSc) {
            $null = az webapp config appsettings set --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --settings $ScepManAppSettings --slot $tempDeploymentSlot
        }
    }

    $existingApplicationKeySc = az webapp config appsettings list --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --query "[?name=='AppConfig:AuthConfig:ApplicationKey'].value | [0]"
    if(![string]::IsNullOrEmpty($existingApplicationKeySc)) {
        $null = az webapp config appsettings set --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --settings BackUp:AppConfig:AuthConfig:ApplicationKey=$existingApplicationKeySc
        $null = az webapp config appsettings delete --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --setting-names AppConfig:AuthConfig:ApplicationKey
    }

    if($true -eq $scHasDeploymentSlots) {
        ForEach($tempDeploymentSlot in $deploymentSlotsSc) {
            $existingApplicationKeySc = az webapp config appsettings list --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --slot $tempDeploymentSlot --query "[?name=='AppConfig:AuthConfig:ApplicationKey'].value | [0]"
            if(![string]::IsNullOrEmpty($existingApplicationKeySc)) {
                $null = az webapp config appsettings set --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --slot $tempDeploymentSlot --settings BackUp:AppConfig:AuthConfig:ApplicationKey=$existingApplicationKeySc
                $null = az webapp config appsettings delete --name $SCEPmanAppServiceName --resource-group $SCEPmanResourceGroup --slot $tempDeploymentSlot --setting-names AppConfig:AuthConfig:ApplicationKey
            }
        }
    }

    # Add ApplicationId and SCEPman API scope in certmaster web app settings
    $CertmasterAppSettings = "{\`"AppConfig:AuthConfig:ApplicationId\`":\`"$($appregcm.appId)\`",\`"AppConfig:AuthConfig:SCEPmanAPIScope\`":\`"api://$($appregsc.appId)\`",\`"AppConfig:AuthConfig:UseManagedIdentity\`":\`"true\`"}".Replace("`r", [String]::Empty).Replace("`n", [String]::Empty)
    $null = az webapp config appsettings set --name $CertMasterAppServiceName --resource-group $SCEPmanResourceGroup --settings $CertmasterAppSettings

    Write-Output "SCEPman and CertMaster configuration completed"
}

Export-ModuleMember -Function Complete-SCEPmanInstallation