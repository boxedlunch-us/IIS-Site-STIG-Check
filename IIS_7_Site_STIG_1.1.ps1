# get operating dir for the script
$ScriptDir = Split-Path $script:MyInvocation.mycommand.path

# Import Modules
Import-Module -Name Microsoft.Powershell.Security
Import-Module Webadministration
Import-Module $ScriptDir\checks.psm1

# Import Ckl
$checklistPath = "$ScriptDir\empty_IIS_Site.ckl"
$ckl = (Select-Xml -Path $checklistPath -XPath /).Node
$stigdata = $ckl.childnodes.stigs.istig.vuln.stig_data
#$vList = $stigdata.attribute_data | where {$_ -like "V-*"}
foreach($a in $stigdata){
    #$a.ParentNode.STIG_DATA
}



# Computername
$computer = 'Server to be scanned'  #<--------- Change This

# Checklist output directory
$saveDirectory = "\\share\development\ricky\temp\iis_sites\$computer\"

# create hastable for export later
$exportTable = @()

# Gets registry key values
function Get-RegKey{
    param(
        [string]$path, [string]$computer, [string]$hive, [string]$value
    )
    $path = $path.TrimStart('\')
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $computer)
    $key = $reg.OpenSubKey($path)
    if(!$value){
        return $key
    } else{
        $result = $key.GetValue($value)
        return $result
    }
    
}

function Set-Stigobject{
    Param($ruletitle,$vulnID,$value,$result)
    $object = New-Object -TypeName PSObject
    $object | Add-Member –MemberType NoteProperty –Name RuleTitle –Value "$ruletitle"
    $object | Add-Member –MemberType NoteProperty –Name VulnID –Value "$vulnID"
    $object | Add-Member –MemberType NoteProperty –Name Value –Value "$value"
    $object | Add-Member -MemberType NoteProperty –Name Result –Value "$result"
    return $object
}

function Set-CklXml{
    Param($stigdata,$vulnID)
    
    $check = $stigdata | Where-Object {$_.attribute_data -like $vulnID}
    $rule = $check.parentnode.STIG_DATA | Where-Object {$_.vuln_attribute -like 'Rule_Title'}
    #$object = New-Object -TypeName PSObject
    #$object | Add-Member –MemberType NoteProperty –Name VULN_ATTRIBUTE –Value $rule.
    return $rule
}

function Set-RuleStatus{
    
}

# gets the imported module for use by script
$modules = Get-Module | Where-Object {$_.moduletype -eq 'Script' -and $_.name -like 'checks*'}

# gets all the commands in the module
$commandlist = $modules.ExportedCommands.values.name | Where-Object {$_ -like 'Get-*'}


    foreach($command in $commandlist)
    {
        # prepares the command to be executed
        $jogatize = (Get-Command $command -CommandType Function).ScriptBlock

        Write-Host("Running $command") -ForegroundColor Yellow
        # running the actual command; feeding it into a variable
        $yourmom = invoke-command $jogatize -ArgumentList $computer

        # get the STIG data corresponding with the vulnerability ID
        $rule = set-cklXml -stigdata $stigdata -vulnID $yourmom.vulnid

        # Set the status field inside the ckl file
        $rule.ParentNode.STATUS = $yourmom.result

        #set the comment field inside the ckl file
        $rule.ParentNode.COMMENTS = $yourmom.comments

        $stigobject = Set-Stigobject -ruletitle $rule.ATTRIBUTE_DATA -vulnID $yourmom.vulnid -result $yourmom.result -value $yourmom.comments
        $exportTable += $stigobject

        $yourmom = $null

    }

# check for the path because if it doesn't exist it can't save because powershell is a crybaby bitch
$testPath = Test-Path $saveDirectory
if($testPath -eq $false){

    New-Item $saveDirectory -type directory

}

# Save the .ckl file with the type of checklist and the computername
$ckl.Save($saveDirectory+ $computer + "_IIS_Site.ckl")