[CmdletBinding()]
param (
    # If you want to install the PowerShell modules, use this flag
    [switch]$installPowerShell,

    # If you want to install the PowerShell tools, use this flag
    [switch]$installTools
)

$scriptLocation = Get-Location

$Global:VerbosePreference = "SilentlyContinue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

Write-Host "Checking Windows version. To install the Azure Stack VPN via PowerShell, you need to be running Windows 8.1 or newer."
if ([Environment]::OSVersion.Version -ge (new-object 'Version' 6, 1)) {
    $osDescription = (Get-WmiObject -class Win32_OperatingSystem).Caption
    Write-Host "You are running $osDescription - the following PowerShell script will continue"
}
else {
    $osDescription = (Get-WmiObject -class Win32_OperatingSystem).Caption
    Write-Host "Unfortunately you're running $osDescription, and this PowerShell script cannot automate the VPN configuration steps." -ForegroundColor Yellow
    Write-Host "Please see your instructor." -ForegroundColor Yellow
    BREAK
}

if ($installPowerShell) {
    Write-Host "Importing base modules and setting the PSGallery as trusted"
    Import-Module -Name PowerShellGet -ErrorAction Stop
    Import-Module -Name PackageManagement -ErrorAction Stop
    Register-PsRepository -Default -ErrorAction SilentlyContinue
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue

    Write-Host "Cleaning up any existing AzureRM or Azure Stack modules from this workstation, to avoid conflicts. Please be patient, this may take a few moments."
    # Clean up any existing AzureRM or AzureStack modules
    $cleanupRequired = $false
    try {
        $psRmProfle = Get-AzureRmProfile -ErrorAction Ignore | Where-Object {($_.ProfileName -eq "2018-03-01-hybrid") -or ($_.ProfileName -eq "2017-03-09-profile")}
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $error.Clear()
    }
    if ($psRmProfle) {
        $cleanupRequired = $true
    }
    $psAzureModuleCheck = Get-Module -Name Azure* -ListAvailable
    $psAzsModuleCheck = Get-Module -Name Azs.* -ListAvailable
    if (($psAzureModuleCheck) -or ($psAzsModuleCheck) ) {
        $cleanupRequired = $true
    }
    if ($cleanupRequired -eq $true) {
        Write-Host "A previous installation of PowerShell has been detected. To ensure full compatibility with the ASDK and lab environment, this will be cleaned up"
        Write-Host "Cleaning...."
        try {
            if ($(Get-AzureRmProfile -ErrorAction SilentlyContinue | Where-Object {($_.ProfileName -eq "2018-03-01-hybrid")})) {
                Uninstall-AzureRmProfile -Profile '2018-03-01-hybrid' -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if ($(Get-AzureRmProfile -ErrorAction SilentlyContinue | Where-Object {($_.ProfileName -eq "2017-03-09-profile")})) {
                Uninstall-AzureRmProfile -Profile '2017-03-09-profile' -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if ($(Get-AzureRmProfile -ErrorAction SilentlyContinue | Where-Object {($_.ProfileName -eq "latest")})) {
                Uninstall-AzureRmProfile -Profile 'latest' -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $error.Clear()
        }
        Get-Module -Name Azs.* -ListAvailable | Uninstall-Module -Force -ErrorAction SilentlyContinue
        Get-Module -Name Azure* -ListAvailable | Uninstall-Module -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $Env:ProgramFiles\WindowsPowerShell\Modules\Azure* -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $Env:ProgramFiles\WindowsPowerShell\Modules\Azs* -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "No existing PowerShell installation detected - proceeding without cleanup."
    }
    if ($cleanupRequired -eq $true) {
        Write-Host "A previous installation of PowerShell has been removed from this system."
        Write-Host "Once you have closed this PowerShell session, delete all the folders that start with 'Azure' from the $Env:ProgramFiles\WindowsPowerShell\Modules"
        Write-Host "Once deleted, rerun the ConfigASDK script. This will reinstall PowerShell for you."
        BREAK
    }
    Write-Host "Installing new AzureRM and Azure Stack modules"
    # Install new modules
    Install-Module -Name AzureRM -RequiredVersion 2.4.0
    Install-Module -Name AzureStack -RequiredVersion 1.7.0
}
else {
    Write-Host "User chose to not install PowerShell modules for AzureRM and Azure Stack"
}

if ($installTools) {
    Write-Host "Downloading and extracting GitHub tools"
    # Download Azure Stack Tools
    Set-Location C:\
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
    invoke-webrequest https://github.com/Azure/AzureStack-Tools/archive/master.zip -OutFile master.zip
    expand-archive master.zip  -DestinationPath . -Force
}
else {
    Write-Host "User chose to not install Azure Stack tools from GitHub"
}

Write-Host "Configuring VPN setup..."
Write-Host "Enabling PSremoting and configuring WinRM"
# Setup the VPN
Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -ne "DomainAuthenticated"}  | Set-NetConnectionProfile -NetworkCategory Private
Enable-PSRemoting -Force
winrm quickconfig -Force
Write-Host "Setting execution policy to RemoteSigned"
Set-ExecutionPolicy RemoteSigned -Force

Write-Host "Obtaining root certificate from your ASDK host"
# Obtain the Cert for ASDK
[string] $hostIP1 = Read-Host -Prompt "Please enter the ASDK Host IP that has been provided to you by your instructor"
$PlainPassword = Read-Host -Prompt "Please enter your ASDK password that has been provided to you by your instructor"
$securePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
Set-Item wsman:\localhost\Client\TrustedHosts -Value $hostIP1 -Concatenate -Force
$azshome = "$env:USERPROFILE\Documents"
Write-Host "Connection-specific files will be saved in $azshome"
New-Item $azshome -ItemType Directory -Force | Out-Null
$UserCred = "azurestack\azurestackadmin"
$credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserCred, $SecurePassword

$cert = Invoke-Command -ComputerName "$hostIP1" -ScriptBlock { Get-ChildItem cert:\currentuser\root | where-object {$_.Subject -like "*AzureStackSelfSignedRootCert*"} } -Credential $credential
if ($cert) {
    if ($cert.GetType().IsArray) {
        $cert = $cert[0] # take any that match the subject if multiple certs were deployed
    }
    $certFilePath = "$azshome\CA-ASDK.cer"
    Write-Host "Saving Azure Stack Root certificate in $certFilePath..." -Verbose
    Export-Certificate -Cert $cert -FilePath $certFilePath -Force | Out-Null
    Write-Host "Installing Azure Stack Root certificate..." -Verbose
    Write-Host "LOOK FOR CERT ACCEPTANCE PROMPT ON YOUR SCREEN!"
    Import-Certificate -CertStoreLocation cert:\LocalMachine\Root -FilePath $certFilePath
}
else {
    Write-Error "Certificate has not been retrieved!"
}

$ConnectionName = "HPE-ASDK"
$existingConnection = Get-VpnConnection -Name $ConnectionName -ErrorAction Ignore
if ($existingConnection) {
    Write-Host "Updating Azure Stack VPN connection named $ConnectionName" -Verbose
    rasdial $ConnectionName /d
    Remove-VpnConnection -name $ConnectionName -Force -ErrorAction Ignore
}
else {
    Write-Host "Creating Azure Stack VPN connection named $ConnectionName" -Verbose
}

Write-Host "Creating VPN Connection"
Add-VpnConnection -Name $ConnectionName -ServerAddress $hostIP1 -TunnelType L2tp -EncryptionLevel Required -AuthenticationMethod MSChapv2 -L2tpPsk $PlainPassword -Force -RememberCredential -PassThru -SplitTunneling
Write-Host "Adding routes to Azure Stack VPN connection named $ConnectionName" -Verbose
Add-VpnConnectionRoute -ConnectionName $ConnectionName -DestinationPrefix 192.168.102.0/24 -RouteMetric 2 -PassThru | Out-Null
Add-VpnConnectionRoute -ConnectionName $ConnectionName -DestinationPrefix 192.168.105.0/27 -RouteMetric 2 -PassThru | Out-Null

Write-Host "Connecting the $ConnectionName VPN"
rasdial.exe $ConnectionName azurestack\azurestackadmin $PlainPassword
Write-Host "Should you disconnect your VPN, you can reconnect manually, and when prompted, enter azurestack\azurestackadmin and $Plainpassword to complete the logon process."
Set-Location $scriptLocation