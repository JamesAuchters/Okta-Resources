#Quick and easy File to write output to - A Lazy mans logging
Start-Transcript ./Okta-ServiceAccountConfig.log 

Import-Module ActiveDirectory
#Bring up an Active Directory command prompt so we can use this later on in the script

#Basic Details for the Service Account & Domain.
$serviceAccountName = "svcOktaAgent"
$serviceAccountUsername = "svcOktaAgent"
$serviceAccountDescription = "svcOktaAgent - Okta AD Agent Service"
$serviceAccountPassword = "1SuperSecretPasswordThatWasRandomlyGenerated!!!"
$serviceAccountOU = "OU=ExampleOU,DC=corp,DC=contoso,DC=com"
$targetUserOUs = @("OU=ExampleOU,DC=corp,DC=contoso,DC=com", "OU=ExampleOU,DC=corp,DC=contoso,DC=com")
$targetGroupOUs = @("OU=ExampleOU,DC=corp,DC=contoso,DC=com")
$domain = Get-ADDomain
$serviceAccountUPN = "svcOktaAgent@$($domain.Forest)"

#Create an AD User
New-ADUser -SamAccountName $serviceAccountUsername -Name $serviceAccountName -DisplayName $serviceAccountName -Path $serviceAccountOU -UserPrincipalName $serviceAccountUPN -CannotChangePassword $true -Description $serviceAccountDescription
Set-ADAccountPassword $serviceAccountUsername -NewPassword $(ConvertTo-SecureString -String $serviceAccountPassword -AsPlainText –Force) –Reset
Enable-ADAccount $serviceAccountUsername

#Assign Permissions for User creation & basic attribute write. 
foreach($TargetOU in $targetUserOUs){
    $UserCommands = @(
        "dsacls `"$TargetOU`" /G $($domain.Name)\$($serviceAccountUsername)`:CC;user"
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;mail;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;userPrincipalName;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;sAMAccountName;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;givenName;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;sn;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;pwdLastSet;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;lockoutTime;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;cn;user",
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;name;user",
        "dsacls `"$TargetOU`" /I:S /G `"$($domain.Name)\$($serviceAccountUsername)`:CA;Reset Password;user`""
    )
    foreach($command in $userCommands){
        CMD /C $command
    }
}

#Permissions required for group push.
foreach($targetOU in $targetGroupOUs){
    $groupCommands = @(
        "dsacls `"$TargetOU`" /G $($domain.Name)\$($serviceAccountUsername)`:CCDC;group"
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;sAMAccountName;group"
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;description;group"
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;groupType;group"
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`;member;group"
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;cn;group"
        "dsacls `"$TargetOU`" /I:S /G $($domain.Name)\$($serviceAccountUsername)`:WP;name;group"
    )
    foreach($command in $groupCommands){
        CMD /C $command
    }
}

Stop-Transcript
