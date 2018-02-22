[CmdletBinding(DefaultParameterSetName='Base64 Credentials')]
[OutputType('System.Management.Automation.PSObject')]
Param
(
    [bool]
    $WebOnly = $False
)

#region functions

Function ConvertFrom-Base64
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [string]
        $InputObject
    )
    
    if($SkipUserSetup) { return }

    try {
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($InputObject))
    }
    catch {
        Write-Error "Failed to decode string"
    }

}

function ConvertTo-Base64()
{

    $auth = $Username + ':' + $Password

    $encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $encodedPassword = [System.Convert]::ToBase64String($Encoded)

    $script:demoUser = $encodedPassword

}

function Remove-SshHostKey
{

    $regPath = 'HKCU:\Software\SimonTatham\PuTTY\SshHostKeys'
    $regKey = (Get-ItemProperty $regPath)

    $RegKey.PSObject.Properties | ForEach-Object {
      if($_.Name -like '*jumphost.cloud-msp.net*'){
        Remove-ItemProperty -Path $regPath -Name $_.Name
      }
    }

}

function Test-TcpPort
{
    Param (

        [Parameter(Mandatory=$true, Position=0)]
        [string]
        $ComputerName,

        [Parameter(Mandatory=$true, Position=1)]
        [int]
        $Port,

        [int]
        $TimeOut = 1000

    )

    # https://msdn.microsoft.com/en-us/library/system.net.sockets.tcpclient(v=vs.110).aspx
    $tcpObject = New-Object System.Net.Sockets.TcpClient 

    $connect = $tcpObject.BeginConnect($ComputerName,$Port,$null,$null) 

    $wait = $connect.AsyncWaitHandle.WaitOne($TimeOut,$false) 
    if (-not $Wait) {
        $response = $false
    } 
    else {
        $error.clear()
        try {
            $tcpobject.EndConnect($connect) | Out-Null
            if ($error[0]) {
                $response = $false
            } else {
                $response = $true
            }
        }
        catch {
            $response = $false
        }
    }

    $response
}

# http://www.jkdba.com/powershell-open-url-in-default-browser/
function Invoke-URLInDefaultBrowser
{
    <#
        .SYNOPSIS
            Cmdlet to open a URL in the User's default browser.
        .DESCRIPTION
            Cmdlet to open a URL in the User's default browser.
        .PARAMETER URL
            Specify the URL to be Opened.
        .EXAMPLE
            PS> Invoke-URLInDefaultBrowser -URL 'http://jkdba.com'
            
            This will open the website "jkdba.com" in the user's default browser.
        .NOTES
            This cmdlet has only been test on Windows 10, using edge, chrome, and firefox as default browsers.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [String] $URL
    )
    #Verify Format. Do not want to assume http or https so throw warning.
    if( $URL -notmatch "http://*" -and $URL -notmatch "https://*")
    {
        Write-Warning -Message "The URL Specified is formatted incorrectly: ($URL)" 
        Write-Warning -Message "Please make sure to include the URL Protocol (http:// or https://)"
        break;
    }
    #Replace spaces with encoded space
    $URL = $URL -replace ' ','%20'
    
    #Get Default browser
    $DefaultSettingPath = 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice'
    $DefaultBrowserName = (Get-Item $DefaultSettingPath | Get-ItemProperty).ProgId
    
    #Handle for Edge
    ##edge will no open with the specified shell open command in the HKCR.
    if($DefaultBrowserName -eq 'AppXq0fevzme2pys62n3e0fbqa7peapykr8v')
    {
        #Open url in edge
        start Microsoft-edge:$URL 
    }
    else
    {
        try
        {
            #Create PSDrive to HKEY_CLASSES_ROOT
            $null = New-PSDrive -PSProvider registry -Root 'HKEY_CLASSES_ROOT' -Name 'HKCR'
            #Get the default browser executable command/path
            $DefaultBrowserOpenCommand = (Get-Item "HKCR:\$DefaultBrowserName\shell\open\command" | Get-ItemProperty).'(default)'
            $DefaultBrowserPath = [regex]::Match($DefaultBrowserOpenCommand,'\".+?\"')
            #Open URL in browser
            Start-Process -FilePath $DefaultBrowserPath -ArgumentList $URL   
        }
        catch
        {
            Throw $_.Exception
        }
        finally
        {
            #Clean up PSDrive for 'HKEY_CLASSES_ROOT
            Remove-PSDrive -Name 'HKCR'
        }
    }
}

function New-SimplePassword
{
    Param(
        [string]
        $Prefix = "Demo",

        [int]
        $SuffixCount = 2
    )

    $pwd = (([char[]]([char]97..[char]120)) + 0..9 | sort {Get-Random})[1..$SuffixCount] -join ''
    $pwd = "$Prefix"+$pwd
    $script:Password = $pwd

}

function Get-UserName
{

    Param (

        $User = $env:USERNAME

    )

    if(($User).IndexOf('.') -gt 0) {
        $script:UserName = $(($($User).Split('.')[0])[0]) + $($User).Split('.')[-1]
    }
    else {
        $script:UserName = $User    
    }

}

Function Get-DnsTxt
{

    if($SkipUserSetup) { return }

    if(-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {

        # attempting old school method
        $txtEntry = Get-DnsTxtNslookup
    }

    try {
        $txtEntry = Resolve-DnsName -Name demorest.cloud-msp.net -Type TXT -ErrorAction Stop
        $txtEntry.Strings
    }
    catch {
        Write-Error "Failed to get DNS TXT record"
    }
}

function Get-DnsTxtNslookup
{
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$env:SystemRoot\System32\nslookup.exe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = "-querytype=TXT -timeout=10 demorest.cloud-msp.net"
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if($stdout -match "demorest.cloud-msp.net") {
        $stdout|%{$_.split('"')[1]}
    }
}

Function ConvertTo-PSCredential {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]      
    Param(

        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [string]
        $InputObject
    )

    if($SkipUserSetup) { return }

    $u = $InputObject.split(':',2)[0]
    $p = $InputObject.split(':',2)[1]

    try {
        if($u -and $p) {
            $ps = ConvertTo-SecureString -AsPlainText -Force -String $p -ErrorAction Stop
            $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $u, $ps -ErrorAction Stop
            if($credential -is [System.Management.Automation.PSCredential]) {
                $script:cred = $credential
            } else {
                Write-Error -Message "Failed to process base64 string"
            }            
        }
        else {
            Write-Error -Message "Failed to process base64 string"
        }
    }
    catch {
        Write-Error -Message "Failed to process base64 string"
    }
}

function Wait-Random {

    if($SkipUserSetup) { return }

    $random = Get-Random -Minimum 1 -Maximum 30

    for($i = 1 ; $i -lt $random ; $i++) {
        Write-Progress -Activity "Throttling mechanism" -PercentComplete ($i/$random*100)    
        Start-Sleep -Seconds 1
    }

    Write-Progress -Activity "Throttling mechanism" -Completed
}

function Start-AwxTemplate
{

    if($SkipUserSetup) { return }


    $params = @{
        'Uri' = 'http://ansible.cloud-msp.net/api/v2/job_templates/'
        'Credential' = $cred
        'ErrorAction' = 'Stop'
    }

    $templates = Invoke-RestMethod @params

    $jobTemplateID = ($templates.results | Where-Object Name -eq "ansibledemo").id


    $hashData = @{
        demo_user = $demoUser
    }

    $extraVars = @{
        extra_vars = $hashData
    }

    $uri = "http://ansible.cloud-msp.net/api/v2/job_templates/$($jobTemplateID)/launch/"

    $params = @{
        'Uri' = $uri
        'Credential' = $cred
        'Method' = 'Post'
        'ContentType' = 'application/json'
        'ErrorAction' = 'Stop'
        'Body' = ($extraVars | ConvertTo-Json)
    }
    
    try {
        $invokeTemplate = Invoke-RestMethod @params
        $jobId = $invokeTemplate.id
        Write-Output "AWX job id: $($jobId)"
    }
    catch {
        Write-Output $_
        Write-Error -Message "Failed to invoke AWX job"
        # exit 1
    }

    $loops = 40
    $wait = 3

    for($i = 1 ; $i -le $loops ; $i++) {

        
        $uri = "http://ansible.cloud-msp.net/api/v2/jobs/$jobId/"

        $params = @{
            'Uri' = $uri
            'Credential' = $cred
            'ErrorAction' = 'Stop'
        }
        $job = Invoke-RestMethod @params
        $status = $job.status

        Write-Output "Checking job id $($jobId): $i of $loops attempts Status = $status"
        if(($status -ne "running") -and ($status -ne "waiting") -and ($status -ne "pending")) {
            break
        }

        Start-Sleep -Seconds $wait

    }

    $status | Out-File -FilePath "$tmpDir\awxstatus.txt"

}

function Get-Putty
{
    Param(

        $PuttyUrl = 'https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe',
        $PlinkUrl = 'https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe'

    )

    $puttyFile = "$tmpDir\putty.exe"
    $plinkFile = "$tmpDir\plink.exe"

    try {
        if(-not (Test-Path -Path $puttyFile)) {
            Invoke-WebRequest -Uri $PuttyUrl -OutFile $puttyFile -ErrorAction Stop
        }
        if(-not (Test-Path -Path $plinkFile)) {
            Invoke-WebRequest -Uri $PlinkUrl -OutFile $plinkFile -ErrorAction Stop
        }
    }
    catch {
        Write-Error -Message "Failed to download putty tools"
    }

}

function Get-PSScript
{
    Param(

        $Url = 'https://raw.githubusercontent.com/tonyskidmore/PSDemoSession/master/PSDemoSession.ps1'
    )

    $outputFile = "$tmpDir\PSDemoSession.ps1"


    try {
        if(-not (Test-Path -Path $outputFile)) {
            Invoke-WebRequest -Uri $Url -OutFile $outputFile -ErrorAction Stop
        }
    }
    catch {
        Write-Error -Message "Failed to download PS script"
    }

}


function Get-Key
{
    Param(

        $Url = "http://jumphost.cloud-msp.net/$UserName.ppk"

    )

    $outputFile = "$tmpDir\$UserName.ppk"
    $retries = 20
    $sleepSeconds = 10

    for($i = 1 ; $i -lt $retries ; $i++) {
        Write-Progress -Activity "Attempting to acquire the key" -PercentComplete ($i/$retries*100)

        if(Test-Path -Path $outputFile) {
            $keyFound = $true
            Write-Progress -Activity "Attempting to acquire the key" -Completed
            break
        }
        else {
            try {
                Invoke-WebRequest -Uri $Url -OutFile $outputFile -ErrorAction SilentlyContinue
            }
            catch {

            }
            if(Test-Path -Path $outputFile) {
                $keyFound = $true
                Write-Progress -Activity "Attempting to acquire the key" -Completed
                break
            }
            else {
                Write-Progress -Activity "Attempting to acquire the key" -PercentComplete ($i/$retries*100) -Status "$i of $retries attempts" -CurrentOperation "Sleeping $sleepSeconds seconds"
                Start-Sleep -Seconds $sleepSeconds
            }
        }
    }

    if(-not $keyFound) { 
        Write-Progress -Activity "Failed to acquire the key" -Completed
        Write-Error "Unable to obtain the key"
    }
    else {
        $true
    }


}

function Invoke-PuttySession
{
    Param(

        [string]
        $Hostname = 'jumphost.cloud-msp.net',

        [string]
        $User = $UserName,

        [string]
        $PrivateKey

    )

    try {
        
        if(-not $PrivateKey) {
            $PrivateKey = (Join-Path -Path $tmpDir -ChildPath "$UserName.ppk")
        }

        $plinkPath = Join-Path -Path $tmpDir -ChildPath 'plink.exe'
        $puttyPath = Join-Path -Path $tmpDir -ChildPath 'putty.exe'

        $testPaths = @($PrivateKey, $plinkPath, $puttyPath)

        foreach($testPath in $testPaths) {

            if(-not (Test-Path -Path $testPath)) {
                Write-Error "Unable to locate $testPath)"
                $failPath = $true
            }
        }

        if($failPath) {
            exit 1
        }
        else {
            Write-Output y | & $plinkPath $User@$Hostname -i $PrivateKey "exit" 2>&1 | Out-Null
            & $puttyPath $User@$Hostname -i $PrivateKey 2>&1 | Out-Null
        }

    }
    catch {
        Write-Error -Message "Failed to run putty session"
    }
}

function New-ProjectSpace
{
    $workingDir = 'PSDemoSession'
    $temp = $env:TEMP
    $script:tmpDir = Join-Path -Path $temp -ChildPath $workingDir

    if(-not (Test-Path -Path $tmpDir)) {
        try {
            $newDir = New-Item -ItemType Directory -Force -Path $tmpDir -ErrorAction Stop
        }
        catch {
            Write-Error -Message "Failed to create working directory"  
        }
    }
}

function Get-OpenPorts {

    $portArray = @()

    $body = @( 
                @{ Destination="ansible.cloud-msp.net"; Port=22 }, 
                @{ Destination="ansible.cloud-msp.net"; Port=80 },
                @{ Destination="ansible.cloud-msp.net"; Port=443 },
                @{ Destination="jumphost.cloud-msp.net"; Port=22 }, 
                @{ Destination="jumphost.cloud-msp.net"; Port=80 },
                @{ Destination="jumphost.cloud-msp.net"; Port=443 }

            )

    $portArray += $body | ForEach-Object { $_.Add('Status', (Test-TcpPort $_.Destination $_.Port)) ;
                                           New-Object -TypeName PSObject -Property $_ }
    $script:PortStatus = $portArray
}

function Get-PortStatus
{
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]
        $Destination,

        [Parameter(Mandatory=$true, Position=1)]
        [int]
        $Port
    )

    if(($PortStatus | Where-Object { ($_.Destination -eq $Destination) -and
                                     ($_.Port -eq $Port) }).Status) {
        $true
    }
    else {
        $false
    }
}

function Get-JobStatus
{

    if(Test-Path -Path "$tmpDir\awxstatus.txt") {
        $jobStatus = Get-Content -LiteralPath "$tmpDir\awxstatus.txt"
        if($jobStatus -eq 'successful') {
            $true
        }
        else {
            $false
        }
    }

}

function Import-XmlCredential
{

    if(Test-Path -Path "$tmpDir\cred.xml") {
        $credential = Import-Clixml -Path "$tmpDir\cred.xml"
        $script:Username = $credential.Username
        $script:Password = $credential.GetNetworkCredential().Password
        $true
    }
    else {
        $false
    }
}

function Export-XmlCredential
{

    if(-not (Test-Path -Path "$tmpDir\cred.xml") -and $Username -and $Password) {
        $pwd = $Password | ConvertTo-SecureString -asPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Username,$pwd)
        $credential | Export-Clixml -Path "$tmpDir\cred.xml"
    }
    else {
        $false
    }
}


#endregion functions

# main script execution
New-ProjectSpace
Get-OpenPorts

if(-not (Import-XmlCredential)) {
    Get-UserName
    New-SimplePassword
    ConvertTo-Base64
    Export-XmlCredential
}


if(-not (Get-JobStatus)) {
    Get-DnsTxt | ConvertFrom-Base64 | ConvertTo-PSCredential

    #Wait-Random
    Start-AwxTemplate
}

Write-Host "Your username is: $UserName" -ForegroundColor Green
Write-Host "Your password is: $Password" -ForegroundColor Green

if( (Get-PortStatus "jumphost.cloud-msp.net" 22) -and (-not $WebOnly)) {
    Get-Putty
    Get-PSScript
    $keyResult = Get-Key

    if($keyResult) { 
        Write-Host "Please now switch to the putty session" -ForegroundColor Green
        Invoke-PuttySession
        Remove-SshHostKey
    }
}
elseif( Get-PortStatus "jumphost.cloud-msp.net" 443) {
    Write-Host "Please now switch to the browser session" -ForegroundColor Green
    Invoke-URLInDefaultBrowser "https://jumphost.cloud-msp.net"
}
else {
    Write-Output "Unable to establish a connection to jumphost.cloud-msp.net"     
}
