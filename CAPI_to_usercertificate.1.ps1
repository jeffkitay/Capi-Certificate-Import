
Param(
[Parameter(Mandatory=$false)][switch]$Silent=$false
)
#Debugging Only
#write-host "Is Silent $silent"
#return


<# CAPI_to_userCertificate.ps1
  PURPOSE: The purpose of this script is to select and publish the public certificates in a user's certificate store
           to their AD userscertificates attribute. The certificate selected must have have the purpose of smart card authentication. 
  
  USAGE: The script should be run as a logon script as the current user (no privledge elevation is required)
  
  CREDITS: Code to select the certificate based on the the purpose was found here: http://poshcode.org/2207
           The Function to Get the AD user and properties was found here: 
           http://stackoverflow.com/questions/2184692/updating-active-directory-user-properties-in-active-directory-using-powershell?rq=1
           If you are able to use the ActiveDirectory Module you can avoid the search function below and implement something like the post by Lain Robertson here:
           http://social.technet.microsoft.com/Forums/en-US/winserversecurity/thread/65a993c7-0d67-4059-aa3f-47dc8a388de5/

  AUTHOR: Jeff Kitay
  Date:#updated 05/15/2019
  Original Author
  Andy Edwards
  DATE: 01/24/2013
  Modified: 03/18/2019 Added GUI Functionality and more reporting
  Modified: 03/15/2013 Added better error reporting. Check for NIH Domain.
  TODO: All info should be sent to application logs for splunk checking. 
         .SYNOPSIS 
            Creates a Timed Message Popup Dialog Box. 
 
        .DESCRIPTION 
            Creates a Timed Message Popup Dialog Box. 
 
        .OUTPUTS 
            The Value of the Button Selected or -1 if the Popup Times Out. 
            
            Values: 
                -1 Timeout   
                 1  OK 
                 2  Cancel 
                 3  Abort 
                 4  Retry 
                 5  Ignore 
                 6  Yes 
                 7  No 
 
        .PARAMETER Message 
            [string] The Message to display. 
 
        .PARAMETER Title 
            [string] The MessageBox Title. 
 
        .PARAMETER TimeOut 
            [int]   The Timeout Value of the MessageBox in seconds.  
                    When the Timeout is reached the MessageBox closes and returns a value of -1. 
                    The Default is 0 - No Timeout. 
 
        .PARAMETER ButtonSet 
            [string] The Buttons to be Displayed in the MessageBox.  
 
                     Values: 
                        Value     Buttons 
                        OK        OK                   - This is the Default           
                        OC        OK Cancel           
                        AIR       Abort Ignore Retry 
                        YNC       Yes No Cancel      
                        YN        Yes No              
                        RC        Retry Cancel        
 
        .PARAMETER IconType 
            [string] The Icon to be Displayed in the MessageBox.  
 
                     Values: 
                        None      - This is the Default 
                        Critical     
                        Question     
                        Exclamation  
                        Information  
             
        .EXAMPLE 
            $RetVal = Show-PopUp -Message "Data Trucking Company" -Title "Popup Test" -TimeOut 5 -ButtonSet YNC -Icon Exclamation 
  #>

function Clean-CerticateStore(){
$ErrorActionPreference = 'silentlycontinue'
$CertsSmartCard,$CertsSmartCardNot,$CertstokeepSAN,$CertstokeepSANNot,$CertstokeepSANOverflow,$CertsExpired,$CertsExpiredNot,$CertsAffialiteA,$CertsAffialiteANot = Get-UserCertificates
##
#Smart card and certs not to keep
#$RemoveExtraCertSmartCard1 = Compare-object -ReferenceObject @($CertsSmartCard| Select-Object)  -DifferenceObject @(  $CertstokeepSANNot | Select-Object)  -PassThru -Property Thumbprint -ExcludeDifferent -IncludeEqual ##
$Catch = $CertstokeepSANNot| Remove-Item -Force ## #-WhatIf
#Expired certs
$RemoveExtraCertsmartCard2 = $CertsExpired
$catch = $RemoveExtraCertsmartCard2 | Remove-Item -Force ##  #-WhatIf
#Expired certs
$Stop=''    
}
function Get-UserCertificates{
    [CmdletBinding()]
    [OutputType([array])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false)] 
        $Param1,

        # Param2 help description
        [Parameter(Mandatory=$false)]        
        [int]
        $Param2,

        # Param3 help description
        [Parameter(Mandatory=$false)]
        [String]
        $Param3
    )
    ##
    $Certstore = Get-ChildItem 'cert:\CurrentUser\My' | sort -unique
    $CertsExpiredNot= $Certstore | ? {(Get-Date $_.NotAfter) -gt (Get-Date)}
    $CertsAffialiteA = $Certstore | ? {$_.subject -match '-a' -and $_.subject -match 'OID.0.9.2342.19200300.100.1' -and $_.subject -notmatch 'ms-org'}
    $CertsExpired = Compare-Object -ReferenceObject @($Certstore | Select-Object)  -DifferenceObject @($CertsExpiredNot | Select-Object)  -PassThru -Property Thumbprint ##    
    $CertsAffialiteANot= Compare-Object -ReferenceObject @( $Certstore | Select-Object) -DifferenceObject @($CertsAffialiteA | Select-Object) -PassThru -Property Thumbprint ##
    ##
    $Certlistfilter=""
    $CertstokeepSAN=@()
    $CertstokeepSANNot=@()
    $CertstokeepSANOverflow=@()
    foreach ($Cert in $Certstore){    
        if ($sanExt= $cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}){
            $sanObjs = new-object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $altNamesStr=[System.Convert]::ToBase64String($sanExt.RawData)
            $sanObjs.InitializeDecode(1, $altNamesStr)
            $Certlistfilter =""
            Foreach ($SAN in $sanObjs.AlternativeNames){
                if ($Certlistfilter){break}
                $SAN = $SAN.strValue
                if ($SAN){
                    $CertListFilter = $SAN | ? {$_ -match '@nih.gov' -and $_ -match "$env:username" -and $_ -notmatch '\$@' -and $Cert.subject -match '-a' -and $Cert.subject -match 'OID.0.9.2342.19200300.100.1'  } # keep ncbi upn
                }
                if ($CertListFilter){
                    $CertstokeepSAN = $Certstokeep + $Cert
                    break
                }
                if ($SAN){
                    $CertListFilter = $SAN | ? {(($_ -match '.gov' -or $Cert.subject -match 'ou=nih') -and ($_-match '\$@' -or $_ -notmatch $env:USERNAME) -and (($Cert.subject -match '-a' -or $Cert.subject -match '-e'-or $Cert.subject -match '-s') -and ($Cert.subject -match 'OID.0.9.2342.19200300.100.1'))  -or $Cert.subject -match 'serialnumber=' )} #remove $ and -a or -e from store
                }
                if ($CertListFilter){
                    $CertstokeepSANNot = $CertstokeepSANNot + $Cert
                    break
                }
                if ($SAN -and !$CertListFilter){
                    $CertListFilter = $SAN
                }
                if ($CertListFilter){
                    $CertstokeepSANOverFlow = $CertstokeepSANOverFlow+ $Cert
                    break
                }
            }
        }
     }
    ##
    $PrevErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'silentlycontinue'
    $Certlistfilter=""
    $CertsSmartCard=@()
    $CertsSmartCardNot=@()
    # Go through every certificate in the current user's "My" store
    $matched = $false
    foreach($Cert in $Certstore){
        $matched = $false
        foreach($extension in $Cert.Extensions){
            if ($matched){
                Break
            }
        # For each extension, go through its Enhanced Key Usages
            foreach($certEku in $extension.EnhancedKeyUsages){
                if ($matched){
                    Break
                }
                if($certEku.friendlyname -match "Smart Card Logon"){
                    $CertsSmartCard= $CertsSmartCard + $Cert
                    $matched=$true
                    Break
                }
            }            
                        
        }
    }
    $ErrorActionPreference = $PrevErrorActionPreference
    $CertsSmartCardNot =  Compare-Object -ReferenceObject  @($Certstore| Select-Object)  -DifferenceObject @($CertsSmartCard | Select-Object)  -PassThru -Property Thumbprint ##
    $ReturnObject=@()
    $ReturnObject = @($CertsSmartCard,$CertsSmartCardNot,$CertstokeepSAN,$CertstokeepSANNot,$CertstokeepSANOverflow,$CertsExpired,$CertsExpiredNot,$CertsAffialiteA,$CertsAffialiteANot)
    [int]$Counter='0'
    Foreach ($obj in $ReturnObject){
    [Array]$ReturnObject[$counter]= $obj | sort -unique
    $Counter++
    }
    $Catch = Return $ReturnObject
}
function Get-LocalFile{
    [CmdletBinding()][OutputType([array])]
    Param
    (
        [Parameter(Mandatory=$false)]$Param1="Default",
        [Parameter(Mandatory=$false)]$Param2="Default"
    )

    $file = "$env:APPDATA\CertImport.log"
    if( Test-Path $file ){
        $lastrun = Get-Content $env:APPDATA\CertImport.log     
    Return $file,$lastrun
    }Else{
    #Return "No file Detected",'000000000000000'
    }
}
function Get-NCBIUser{
    [CmdletBinding()][OutputType([object])]
        Param( 
        [parameter(Mandatory=$false, ValueFromPipeLine=$false)][Alias("User")][string]$samid=$User
        )
     if (!$samid){
     $samid = $env:USERNAME
     }
     $searcher=New-Object DirectoryServices.DirectorySearcher
     $OU = New-Object System.DirectoryServices.DirectoryEntry("LDAP://OU=People,dc=ncbi,dc=nlm,dc=nih,dc=gov")
     $searcher.Filter="(&(objectcategory=person)(objectclass=user)(sAMAccountname=$samid))"
     $searcher.SearchRoot = $OU
     $searcher.SearchScope = "Subtree"
     $aduser=$searcher.FindOne()
     if ($aduser -ne $null ){
        $aduser= $aduser.getdirectoryentry()
     }
     return $aduser
}
function Get-CertMatch{
    [CmdletBinding()][OutputType([string])]
    Param
    (
        [Parameter(Mandatory=$false)]$ParamLocal=@{},
        [Parameter(Mandatory=$false)]$ParamAD=@{}
    )

    $file = "$env:APPDATA\CertImport.log"
    if( Test-Path $file ){
        $lastrun = Get-Content $env:APPDATA\CertImport.log     
    Return $lastrun
    }
}
Function Show-Messagebox{ 
    [CmdletBinding()][OutputType([int])]
        Param( 
        [parameter(Mandatory=$true, ValueFromPipeLine=$false)][Alias("Msg")][string]$Message, 
        [parameter(Mandatory=$true, ValueFromPipeLine=$false)][Alias("Ttl")][string]$Title = $null, 
        [parameter(Mandatory=$true, ValueFromPipeLine=$false)][Alias("Duration")][int]$TimeOut = 0, 
        [parameter(Mandatory=$true, ValueFromPipeLine=$false)][Alias("But","BS","Button")][ValidateSet( "OK", "OC", "AIR", "YNC" , "YN" , "RC")][string]$ButtonSet = "OK", 
        [parameter(Mandatory=$false, ValueFromPipeLine=$false)][Alias("ICO")][ValidateSet( "None", "Critical", "Question", "Exclamation" , "Information" )][string]$IconType = "None",
        [parameter(Mandatory=$false, ValueFromPipeLine=$false)][switch]$ISSilent = $silent  
         ) 
 
    $ButtonSets = "OK", "OC", "AIR", "YNC" , "YN" , "RC" 
    $IconTypes  = "none", "critical", "question", "exclamation" , "information" 
    $IconVals = 0,16,32,48,64 
    if((Get-Host).Version.Major -ge 3){ 
        $Button   = $ButtonSets.IndexOf($ButtonSet.ToUpper()) 
        $Icon     = $IconVals[$IconTypes.IndexOf($IconType.ToLower())] 
        } 
    else{ 
        $ButtonSets|ForEach-Object -Begin{$Button = 0;$idx=0} -Process{ if($_.Equals($ButtonSet)){$Button = $idx           };$idx++ } 
        $IconTypes |ForEach-Object -Begin{$Icon   = 0;$idx=0} -Process{ if($_.Equals($IconType) ){$Icon   = $IconVals[$idx]};$idx++ } 
        } 
     if (-not $Silent){   
     $window = new-object -comobject wscript.shell
     $return = $window.popup($message,$time,$title,$Button+$Icon) 
     return $return
     }Else{
     Return -1
     }  
}
function Update-NameMapping {
    [CmdletBinding()][OutputType([string])]
        Param( 
        [parameter(Mandatory=$true, ValueFromPipeLine=$false)][object]$cert
        ) 
    
    #$cert = $CertsAffialiteA
    $issuer = ""
    $subject = ""
    $paths = ''

    $paths = [Regex]::Replace($cert.Issuer, ',\s*(CN=|OU=|O=|DC=|C=)', '!$1') -split "!"

    # Reverse the path and save as $issuer
	for ($i = $paths.count -1; $i -ge 0; $i--) {
		$issuer += $paths[$i]
		if ($i -ne 0) {
			$issuer += ","
		}
	}

    $paths = ""
    # Do the same things for $cert.subject
    $paths = [Regex]::Replace($cert.subject, ',\s*(CN=|OU=|O=|DC=|C=)', '!$1') -split "!"


    # Reverse the path and save as $subject
	for ($i = $paths.count -1; $i -ge 0; $i--) {
		$subject += $paths[$i]
		if ($i -ne 0) {
			$subject += ","
		}
	}
    $subject = $subject -replace '\+ ',''

    # Now $cert.subject is reversed:

    # Format as needed for altSecurityIdentities
    $newcert = "X509:<I>$issuer<S>$subject"
    return $newcert
    
}

## Initialize
#Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear(); Clear-Host
$ErrorActionPreference='SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
if ($host.Name -match 'ise host'){$DebugPreference = 'Continue';$ErrorActionPreference='Continue';CLS} # Turns on debugging output
$user = $env:USERNAME
$domain= $env:USERDOMAIN
$ekuName = "Smart Card Logon" # '-a credential'
$sccert = ""
$lastrun = ""
$smtpserver = "mailgw"
$mailfrom = "systems.pc@ncbi.nlm.nih.gov"
$mailto = "pc.systems@ncbi.nlm.nih.gov"
$PIVmatchAdCertbool=$false
## Initialize Functions
$UserCertA = ""
$CleanCerts = Clean-CerticateStore
$CertsSmartCard,$CertsSmartCardNot,$CertstokeepSAN,$CertstokeepSANNot,$CertstokeepSANOverflow,$CertsExpired,$CertsExpiredNot,$CertsAffialiteA,$CertsAffialiteANot = Get-UserCertificates
$UserFile = Get-LocalFile
$UserObject =Get-NCBIUser
$CertsAffialiteA = $CertsAffialiteA | Sort-Object -Property NotAfter -Descending 

if($CertsAffialiteA.Count -gt 1){
    foreach ($Choice in $CertsAffialiteA){
        $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
        $title = "There Are Multiple Valid PIV Certificates"
        $message = "`nSelect the appropriate certificate`n`n$($Choice.subject)`n"    
        $Returnvalue=Show-Messagebox -message $message -title $title -timeout '120' -buttonset 'yn' -icontype 'exclamation'
        If (($Returnvalue -eq 1) -or ($Returnvalue -eq 6) -or ($Returnvalue -eq -1) ){
            $UserCertA = $Choice
            break
        }
    }

}
if($true -ne $UserCertA){
    $UserCertA=$CertsAffialiteA  | ? {$CertsAffialiteA.NotAfter -lt (get-date).AddYears(5)} | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
}


if (($UserCertA -and $UserFile -and $UserObject) -or $true){
    $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
    $title = "Pre-Run Detection Results"
    [boolean]$PIVmatchAdCertbool= -not (-not ($UserObject.userCertificate -match $UserCertA.RawData)) # does not report true correctly have to use false
    $messagePIVmatchAD = "`nUser file certificate match with AD user certificate `n$PIVmatchAdCertbool`n"
    $messagePIV = "`nPIV Certificate detected.`n$($UserCertA.Subject)`n$($UserCertA.Thumbprint)`n"
    $messageUserFile="`nLocal User File`n$UserFile`n"
    $messageUserObject="`nUser Object`n$($UserObject.userPrincipalName)`n"
    $message = $messagePIVmatchAD + $messagePIV + $messageUserFile + $messageUserObject
   
    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'information'
    $Message
}
if ( $domain -notmatch "NCBI_NT") {
    #Write-Host "Wrong Domain Exiting"
    $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
    $title = "NCBI_NT Domain Only - Wrong Domain Exiting"
    $message = "You are logged into the 'NIH' domain. Log into the NCBI_NT domain and run this application again." 
    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'critical'
    $Message
    exit
}
if (!$UserCertA) {
    $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
    $title = "No PIV Certificate Detected"
    $message = "No PIV Certificate detected. This will exit with no action." 
    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'critical'
    $Message
    exit
} 
if (!$UserObject) {
    $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
    $title = "Not Able To Get AD Results"
    $message = "Not able to get AD results. This will exit with no action." 
    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'critical'
    $Message
    exit
} 
if (!($PIVmatchAdCertbool)){
    $file,$lastrun = Get-LocalFile    
    #Write-Host "Checking if user wants to force update"
    $button = 'YN' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
    $title = "Certificate Needs To Be Uploaded."
    $message = "Choosing 'Yes' will force the PIV certificate to be uploaded if the latest is not published in AD?" 
    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset $button -icontype 'exclamation'
    If (($Returnvalue -eq 1) -or ($Returnvalue -eq 6) -or ($Returnvalue -eq -1) ){
        $Catch = Remove-item -path "$env:APPDATA\CertImport.log" -Force
        $lastrun=""
    }
} 

if( $UserFile -and $PIVmatchAdCertbool){
    $lastrun = Get-Content $env:APPDATA\CertImport.log    
    #Write-Host "Checking if user wants to force update"
    $button = 'YN' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
    $title = "This Has Already Been Run On This Device."
    $message = "Do not rerun this unless directed.`nChoosing 'Yes' will force the PIV certificate to be uploaded if the latest is not published in AD?" 
    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset $button -icontype 'exclamation'
    If ($Returnvalue -eq 1 -or $Returnvalue -eq 6){
        Remove-item -path "$env:APPDATA\CertImport.log" -Force
        $lastrun=""
    }
} 

if (!$Lastrun){
        if (!($PIVmatchAdCertbool)) {        
                # The the thumprints do not match or there is no certificate published for the user
                # Proceed to publish the most recent certificate
                if ($UserCertA.Count -eq 1){
                $UserCert= $UserCertA[0].RawData
                }
                $RS = $UserObject.userCertificate.Clear()
                $RS = $UserObject.CommitChanges()
                $RS = $Error.Clear()
                $RS = $UserObject.InvokeSet("userCertificate", $UserCert)
                $RS = $UserObject.CommitChanges()
                ###Verify Name Mapping

                if ( !$? ) {
                    
                    #send email alert that publishing certificate failed for the specified user
                    #Send-MailMessage -From $mailfrom -Subject "publishing certificate failed" -To $mailto -Body "Publishing the Smart Card Certificate for $domain\$user on  computer: $env:COMPUTERNAME failed with error $Error[0]. `n$UserCertA  Please follow up." -Priority High -SmtpServer $smtpserver
                    $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
                    $title = "PIV Certificate Upload Failed"
                    $message = "PIV upload failed. The certificate in Active Directory is not correct" 
                    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'critical'
                    $message
                } Else {
                    #Write a log file with the certificates thumbprint so that we only update if the certificate changes.
                    #Write-Host "Smart Card Certificate Successfully Imported into userCertificate attribute"
                    $UserCertA.Thumbprint > $env:APPDATA\CertImport.log
                    $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
                    $title = "PIV Certificate Upload Successful"
                    $message = "PIV upload is successful. The certificate in Active Directory is now correct" 
                    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'exclamation'
                    $message

                }

            } Else {
                # Debugging only
                #Write-Host "You already have the latest certificate published"
                $UserCertA.Thumbprint > $env:APPDATA\CertImport.log
                $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
                $title = "Latest Certificate Already Published"
                $message = "PIV upload not required. You already have the latest certificate published" 
                $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'information'
                $Title
            }
        }Else {
        # Debugging only
        #Write-Host "CertImport.log shows we imported the latest version already. Or there was no ExpiredNotcertificate found."    
        $button = "OK"
        $title = "Nothing To Do"
        $message = "`n$Userfile on device shows latest version already." 
        $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'information'
        $Message
}


#$UserCertA = Get-LocalCertPIVA
$UserFile = Get-LocalFile
$UserObject =Get-NCBIUser
if ((-not ($UserObject.userCertificate -match $UserCertA.RawData))){
    $RS=Remove-item -path "$env:APPDATA\CertImport.log" -Force
    $UserFile = Get-LocalFile
}ElseIF(!(Test-Path -Path $env:APPDATA\CertImport.log)){
    $RS=$UserCertA.Thumbprint > $env:APPDATA\CertImport.log
}


#Update Name Mapping
if ($UserCertA -and $UserFile -and $UserObject){
    $newcertmap = ''
    $newcertmap = Update-NameMapping -cert $UserCertA
    if ($UserObject.altSecurityIdentities -notcontains $newcertmap){
        $UserObject.altSecurityIdentities.Add($newcert)
        $UserObject.CommitChanges()
        $UserObject =Get-NCBIUser
    }
}



if ($UserCertA -and $UserFile -and $UserObject -or $true){
    $button = 'OK' # OK only; https://docs.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction.msgbox?view=netframework-4.7.2
    $title = "Post-Run Detection Results"
    $PIVmatchAdCertbool= -not (-not ($UserObject.userCertificate -match $UserCertA.RawData)) # does not report true correctly have to use false
    $messagePIVmatchAD = "`nUser file certificate match with AD user certificate `n$PIVmatchAdCertbool`n"
    $messagePIV = "`nPIV Certificate detected.`n$($UserCertA.Subject)`n$($UserCertA.Thumbprint)`n"
    $messageUserFile="`nLocal User File`n$UserFile`n"
    $messageUserObject="`nUser Object`n$($UserObject.userPrincipalName)`n"
    if ($UserObject.altSecurityIdentities -contains $newcertmap){
        $messageNameMap = "`nName Mapped Correctly to Alt Credentials.`n"
    }ELSE{
        $messageNameMap = "`nName Mapped Not Correct in Alt Credentials.`n"
    }
    If ($PIVmatchAdCertbool){
    Try{
        $lastruntime = Get-ChildItem $env:APPDATA\CertImport.log
        $lastruntime.LastAccessTime = $lastruntime.Lastwritetime = get-date
    }
    Catch{
        Throw
    }

}

    $message = $messagePIVmatchAD + $messagePIV + $messageUserFile + $messageUserObject + $messageNameMap   
    $Returnvalue=Show-Messagebox -message $message -title $title -timeout '60' -buttonset 'ok' -icontype 'information'
    $Message
}





