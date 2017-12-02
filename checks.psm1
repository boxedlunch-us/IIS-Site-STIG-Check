function Set-ReturnObject{ 
    param($vulnid,$comments,$result)   
    $returnObject = New-Object psobject -Property @{
        vulnid = $vulnid
        comments = $comments
        result = $result
    }
    return $returnObject
}

function Get-V13620
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )
    
    # Set the current vulnID
    $vulnID = 'V-13620'

    # Script start
    Import-Module WebAdministration

    # get list of sites
    $sites = Get-Website

    # get ssl bindings 
    $sslSites = Get-ChildItem IIS:\SslBindings | Where-Object {$_.port -eq '443'} 

    # get just the thumbprints from the site certs
    $thumbprints = $sslSites | % {$_.thumbprint}

    #get certs
    $certs = Get-ChildItem CERT:LocalMachine/My | Where-Object {$thumbprints -contains $_.thumbprint}

    # collect results <-- probably a better way to do this***
    $results = @()
    foreach($k in $certs){

        if($k.getissuername() -match '(CA\W)' -or $k.subject -match $computer){
            $result = 'NotAFinding' 
            $results += $result
        }
        else{
            $result = 'Open'
            $results += $result
        }
    }

    # check result table
    $asdf = $results -match 'Open'

    # checking to see if there are any matches, indicating a noncompliant value
    if($asdf.count -gt 0){
        $resultObject = 'Open'
    }else{
        $resultObject = 'NotAFinding'
    }


    #create object to captuer results and relevant info for STIG viewer
    $returnObject = New-Object psobject -Property @{
        vulnid = ''
        comments = ''
        result = ''
    }


    #comment if necessary
    $returnObject.comments = 'Only machine certs are present outside of RWCP'
    $returnObject.vulnid = $vulnID
    $returnObject.result = $resultObject

    return $returnObject



}

function Get-3333
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer 

    )
    # 
    # V-3333
    #
    $vulnid = 'V-3333'

    #get list of websites
    $k = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module Webadministration
        Get-Website
        #return $sites
    } 

    foreach($item in $k){
        $flag = $false

        #check to see if sites are based on the system drive
        if($item.physicalPath.Contains('C:\') -or $item.physicalPath.Contains('%SystemDrive%')){
            $flag = $true
        }

        if($flag = $true){
            $result = 'Open'
        }else{
            $result = 'NotAFinding'

        }
    }

    $object = Set-ReturnObject -vulnid $vulnid -comments $k.ToString() -result $result

    return $object
}

function Get-3963
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )
    
    $vulnid = 'V-3963'

    # Checking for the existence of regkey
    $mong = get-regKey -hive localmachine -path \SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs\ -computer $computer

    if($mong -eq $null){
        $result = 'NotAFinding'
        $mong = 'Regkey does not exist'

    }else{
        $result = 'Open'
        $mong = 'Regkey exists'
    }

    $object = Set-ReturnObject -vulnid $vulnid -comments $mong -result $result

    return $object

}

function Get-6373
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    $vulnid = 'V-6373'

    # This requires input from the BTS staff
    $result = 'Open'
    $comment = 'BTS developers input required'

    $object = Set-ReturnObject -vulnid $vulnid -comments $comment -result $result

    return $object
}

function Get-6531
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # 
    # V-6531 A private web-sites authentication mechanism must use client certificates.
    #
    $vulnid = 'V-6531'

    # hash for collecting values
    $k = @()
    $k = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module WebAdministration
        $sites = Get-Website

        # hash to capture objects
        $pHash = @()
        foreach ($item in $sites)
        {
            $pObject = New-Object psobject -Property @{
                sitename = ''
                sslflags = ''
            }
            $siteName = $item.name
            $webBinding = Get-WebBinding -Name $sitename | Where-Object protocol -eq 'https'
            if($webBinding -ne $null)
            {
            
                $configProp = Get-WebConfigurationProperty -Filter /system.webserver/security/access -Location $sitename -name '*'
                #$configProp |Get-Member $configProp.sslflags
                $pObject.sitename = $siteName
                $pObject.sslflags = $configProp.sslflags
                $pHash += $pObject     
        
            }
        }

        $pHash
    
    }

    $flag = $false
    foreach ($item in $k)
    {
        if ($item.sslflags -notmatch 'Require' )
        {
            $flag = $true
            $comments = 'its broke' #<--- Fix this
        }else{
            #nothing
        }
    
    
    }

    if ($flag -eq $false)
    {
        $result =  'NotAFinding'
    }else{
        $result = 'Open'
    }

    # create object to return values for ckl
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result

    return $object
}

function Get-6724
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    #
    # V-6724 All web-sites must be assigned a default Host header.
    #
    $vulnid = 'V-6724'

    #array sorta
    $localSite = @()
    $localSite = Invoke-Command -ComputerName $computer -ScriptBlock {
    
        $sitehash = @()

        $sites = Get-Website
        $sites | ForEach-Object {
            $siteobject = New-Object psobject -Property @{
                sitename = ''
                bindingport = ''
                hostHeader = ''
                count = ''
                result = ''
            }
            $dammit = Get-WebBinding -Name $_.name

            $siteobject.hostHeader = $dammit.bindinginformation | %{$_.split(':')[-1]}
            $siteobject.bindingport = $dammit.bindinginformation | %{$_.split(':')[-2]}
            $siteobject.sitename = $_.name
            $siteobject.result = $siteobject.hostHeader -eq ''
            $sitehash += $siteobject
        }

        return $sitehash

    
    }


    $flag = $false
    foreach ($i in $localsite)
    {
        if ($i.hostheader.Count -gt 1)
        {
            foreach ($t in $i.hostHeader)
            {
                if($t -eq '')
                {
                    $flag = $true
                }
            }
    
        }else{
            if($i.hostHeader -eq ''){
                $flag = $true
            }
    
        }
  
    }


    if ($flag -eq $true)
    {
        $result = 'Open'
        $comments = 'No host header present'
    }else{
        $result = 'NotAFinding'
        $comments = 'Host header present or N/A'
    }

    # create object to return values for ckl
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result

    return $object
}

function Get-6755
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )
    
    #
    # V-6755 Directory Browsing must be disabled.
    #

    $vulnid = 'V-6755'

    $jogatize = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module WebAdministration

        #get sites
        $sites = Get-Website

        $flag = $false

        $sites | ForEach-Object {
            $sitename = $_.name
            $mong = Get-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath "IIS:\Sites\$sitename"
            if($mong.value -eq $true){
                $flag = $true
            }
        

        }

        return $flag

    }


    if($jogatize -eq $true)
    {
        $result = 'Open'
    }
    else{
        $result = 'NotAFinding'
    }

    # create object to return values for ckl
    $object = Set-ReturnObject -vulnid $vulnid -comments '' -result $result
    
    return $object
}

function Get-13686
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )
    $vulnid = 'V-13686'

    $result = 'NotAFinding'

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments 'Remote uploading is not being performed.' -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13688
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )
    $vulnid = 'V-13688'
    $returned = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module WebAdministration
        #get list of sites
        $sites = Get-Website

        # create object used to collect log info
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Web.Administration')
        $iis = New-Object Microsoft.Web.Administration.ServerManager

        # table to hold values
        $table = @()


        ##This can be done better@'
        # loop thru sites to check log parameters
        foreach($s in $sites){
    
            # create object to insert into table
            $stats = New-Object psobject -Property @{
                site_name = ''
                logfile_enabled = ''
                fields = ''
                result = ''
                comments = ''
            }

            #add sitename to object
            $stats.site_name = $s.name

            # get iis properties for $s
            $web = $iis.Sites[$s.name]

            #check for logfile enabled parameter
            $stats.logfile_enabled = $web.logfile.Enabled

            $fields = $web.LogFile.LogExtFileFlags

            # add fields to object
            $stats.fields = $fields

            # check to see if the require fields are being logged
            if ($fields -like '*ProtocolVersion*' -and
                $fields -like '*ClientIp*' -and
                $fields -like '*UserName*' -and
                $fields -like '*date*' -and
                $fields -like '*time*' -and
                $fields -like '*method*' -and
                $fields -like '*uriquery*' -and
                $fields -like '*referer*' -and
                $fields -like '*httpstatus*' -and
                $fields -like '*httpstatus*' -and
            $fields -like '*httpstatus*')
            {
                $stats.result = 'NotAFinding'
            }else{
                $stats.result = 'Open'
            }
            $table += $stats
      
        }
        return $table
    }


    # find the open result values
    $openCount = $returned | Where-Object {$_.result -eq 'Open'}

    # find the count of false object values
    $disabledCount = $returned | Where-Object {$_.logfile_enabled -eq $false }

    # check for the count of both
    if($openCount.count -ge 1 -or $disabledCOunt.count -ge 1){
        $result = 'Open'
    }else{
        $result = 'NotAFinding'
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $returned.fields.value.tostring() -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13689
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13689 Access to the web-site log files must be restricted.
    $vulnid = 'V-13689'

    # remotely invoke command
    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock{
        
        #create object to store results
        $return = New-Object psobject -Property @{
            accounts = ''
            result = ''
        }
    
        # get acl of IIS logs
        $logfileACL = Get-Acl 'c:\inetpub\logs\LogFiles'

        # check for the allowed users/groups and expose non compliance
        $logfileACL | ForEach-Object{
            $weird = $_.access | Where-Object{$_.identityreference -notmatch 'Administrators' -and $_.identityreference -notmatch 'SYSTEM' -and $_.identityreference -notmatch 'TrustedInstaller'} 
        }

        if($weird -ne $null)
        {
            $result = 'Open'
        }else{
            $result = 'NotAFinding'
        }

        $mong = $weird | ForEach-Object{$_.identityreference.value}

        $return.accounts = $mong -join ' '
        $return.result = $result

        return $return
    }    

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $invReturn.accounts -result $invReturn.result
    
    #return object for use in parent script
    return $object


}

function Get-13694
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13694
    $vulnid = 'V-13694'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
    
        Import-Module webadministration

        # get all websites
        $sites = get-website

        # get only ssl sites
        $sites = $sites | Where-Object{$_.bindings.collection -match ':443'}

        #hashtable for sites
        $table = @()

        # Loop thru sites for sslflags
        foreach ($s in $sites)
        {
            $configProp = Get-WebConfigurationProperty -Filter /system.webserver/security/access -Location $s.name -name '*'
  
            # create object to hold ssl flag values
            $stats = New-Object psobject -Property @{
                site_name = ''
                sslflags = ''
                result = ''

            }


            $sitename = $s.name
            
            # set sitenames ans sslflag results
            $stats.site_name = $sitename
            $stats.sslflags = $configProp.sslflags
            
            # check for requirecert value
            if($stats.sslflags -match 'ssl128'){
                $stats.result = 'NotAFinding'
            }else{
                $stats.result = 'Open'
            }

            # add object to hash
            $table +=$stats
        }


        return $table

        <#if(($table -match 'Open').count -gt 0){
                $result = 'Open'
                }else{
                $result = 'NotAFinding'
                }
        #>
    }

    if(($invReturn -match 'Open').count -gt 0){
        $result = 'Open'
    }else{
        $result = 'NotAFinding'
    }

    $comments = ($invReturn | Where-Object{$_.result -eq 'Open'} | %{$_.site_name}) -join ' '

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments  -result $result
    
    #return object for use in parent script
    return $object



}

function Get-13702
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13702 The Content Location header must not contain proprietary IP addresses.
    $vulnid = 'V-13702'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module webadministration 

        # get websites
        $sites = Get-Website

        #create array to hold objects
        $table = @()

        foreach($s in $sites){
            $sitename = $s.name

            $kObject = New-Object psobject -Property @{
                sitename = ''
                alternateHostName = ''
            }

            try{
                $configprop = Get-WebConfigurationProperty -Filter /system.webserver/serverRuntime -Location $sitename -Name '*'

                # create object to collect serverRuntime info


                $kObject.sitename = $sitename
                $kObject.alternateHostName = $configprop.alternateHostName
            }
            catch{
                $kObject.sitename = $sitename
                $kObject.alternateHostName = 'Error encountered while retrieving parameter.'
            }
            $table += $kObject
        }

        # get blank alternatehostname entries
        $blank = $table | Where-Object{$_.alternatehostname -eq ''}



        #return object for compliance determination
        return $blank
    }

    if($invreturn -ne $null -or $blank -ne '')
    {
        $result = 'Open'
        $comments = $invreturn.sitename -join ' '
        #need to add site names for comment
    }else{
        $result = 'NotAFinding'
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13703
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13703 The website must have a unique application pool.
    $vulnid = 'V-13703'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module webadministration

        $sites = get-website

        $appPools = @()
        foreach($s in $sites){
            $appPools += $s.applicationpool
        }

        # select only unique application pools
        $r = $appPools | Select-Object -Unique

        $comp = Compare-Object -ReferenceObject $r -DifferenceObject $appPools

        return $comp
    }

    if($invReturn.inputobject -ne $null){
        $result = 'Open'
        $commments = $invReturn.inputobject -join ' '
    }else{
        $result = 'NotAFinding'
        $comments = ''
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13704
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13704
    $vulnid = 'V-13704'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
    ####
    # Code goes here
    ####
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments comments -result result
    
    #return object for use in parent script
    return $object


}

function Get-13705
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13705
    $vulnid = 'V-13705'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-WebConfiguration $applicationPoolsPath -Location IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    requestLimitValue = $appPool.applicationPoolDefaults.recycling.periodicRestart.requests  

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.requestlimitvalue -ne 0}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13706
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13706
    $vulnid = 'V-13706'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-WebConfiguration $applicationPoolsPath -Location IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    virtualMemoryLimit = $appPool.applicationPoolDefaults.recycling.periodicRestart.memory

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.virtualMemoryLimit -eq 0}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13707
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13707
    $vulnid = 'V-13707'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-WebConfiguration $applicationPoolsPath -Location IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    privateMemoryLimit = $appPool.applicationPoolDefaults.recycling.periodicRestart.privatememory

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.privateMemoryLimit -eq 0}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13708
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13708
    $vulnid = 'V-13708'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
         #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    idleTimeout = $appPool.processModel.idleTimeout.Minutes

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.idleTimeout -gt 20}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13709
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13709
    $vulnid = 'V-13709'

        $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
         #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    queueLength = $appPool.queueLength

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.queueLength -gt 1000}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13710
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13710
    $vulnid = 'V-13710'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

         #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    pingEnabled = $appPool.processModel.pingingEnabled

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.processModel.pingingEnabled -eq $false}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13712
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13712
    $vulnid = 'V-13712'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

                 #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    rapidFailProtection = $appPool.failure.rapidFailProtection

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.rapidFailProtection -eq $false}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13713
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-13713
    $vulnid = 'V-13713'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

                                 #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit parameter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    identityType = $appPool.processModel.identityType

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | Where-Object{$_.identityType -notmatch 'amed\\(.*)\.[^\s]+|ApplicationPoolIdentity|network(.*)'}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-15334
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

    # V-15334
    $vulnid = 'V-15334'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
    
                                               #import IIS module
        import-module webadministration

        #get list of application pools
        $sites = get-childitem IIS:\sites\

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #parameter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit parameter
        foreach($s in $sites){

                #retrieve sites
                #"dis"
                $name = $s.name
                $sitesInfo = Get-ItemProperty -Path IIS:\sites\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    sitename = $s.name
                    bindings = $s.bindings.Collection | foreach-object{$_.bindinginformation} | out-string

                }

                #remove ip addresses, host headers, newline, and asterisks
                $object.bindings = $object.bindings -replace "[a-z]|\.|\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\*|`n",""

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable


    }

    #comparison is excluding port 80 and 443 sites
    $comp = $invReturn | where-object{$_.bindings -notmatch ":80:|:443:"}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.bindings}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26011
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26011
    $vulnid = 'V-26011'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        #import IIS module
        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

            #get list of application pools and retrieve requestlimit parameter
            foreach($o in $sites){

                $sitename = $o.name
    
                $compilation = Get-WebConfigurationProperty -Filter "/system.web/compilation" -Location IIS:\sites\$sitename -name '*'
                $compilation = $compilation.attributes | where{$_.name -match 'debug'}

                $object = New-Object PSObject -Property @{
                    sitename = $o.name
                    compDebug = $compilation.value

                }

                $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.compDebug -notmatch $false}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.compDebug}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}
#
function Get-26026
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26026
    $vulnid = 'V-26026'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        #import IIS module
        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

            #get list of application pools and retrieve requestlimit parameter
            foreach($o in $sites){

                $sitename = $o.name
    
                $machineKey = Get-WebConfigurationProperty -Filter "/system.web/machineKey" -Location IIS:\sites\$sitename -name '*'

                $object = New-Object PSObject -Property @{
                    sitename = $o.name
                    machineKey = $machineKey.validation
                }

                $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.machinekey -notmatch 'SHA1'}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.machinekey}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26031
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26031
    $vulnid = 'V-26031'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $eMode = get-WebConfiguration -Filter "/system.webServer/httpErrors" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                emode = $emode.errormode
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.emode -notmatch 'DetailedLocalOnly' -or $_.emode -notmatch 'Custom'}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.emode}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26034
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26034
    $vulnid = 'V-26034'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $secPol = get-WebConfiguration -Filter "/system.web/trust" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                secpol = $secpol.level
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.secpol -match 'High' -or $_.secpol -match 'Full'}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.secpol}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26041
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26041
    $vulnid = 'V-26041'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

    import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfiguration -Filter "/system.webserver/security/requestfiltering/requestlimits" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                maxAllowedContentLength = $request.maxAllowedContentLength
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.maxAllowedContentLength -notmatch 30000000}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.secpol}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26042
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26042
    $vulnid = 'V-26042'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

    import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfiguration -Filter "/system.webserver/security/requestfiltering/requestlimits" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                maxUrl = $request.maxUrl
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.maxUrl -notmatch 4096}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.maxUrl}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26043
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26043
    $vulnid = 'V-26043'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfiguration -Filter "/system.webserver/security/requestfiltering/requestlimits" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                maxQueryString = $request.maxQueryString
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.maxQueryString -notmatch 2048}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.maxUrl}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26044
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26044
    $vulnid = 'V-26044'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
       import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters"

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                allowHighBitCharacters = $request.value
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.allowHighBitCharacters -notmatch $false}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.allowHighBitCharacters}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26045
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26045
    $vulnid = 'V-26045'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
       import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                allowDoubleEscaping = $request.value
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.allowDoubleEscaping -notmatch $false}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.allowDoubleEscaping}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26046
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-26046
    $vulnid = 'V-26046'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
       import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted"

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                allowUnlisted = $request.value
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.allowUnlisted -notmatch $false}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.allowUnlisted}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-2267
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-2267
    $vulnid = 'V-2267'


    $result = 'Open'
        
    $comments = 'Handler blacklist must be created'

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-2263
{
    param
    (
        [String]
        [Parameter(Mandatory=$true)]
        $computer
    )

        # V-2263
    $vulnid = 'V-2263'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
      
      #get local cert store
      $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
      $store.Open("ReadOnly")
      $certs = $store.Certificates


        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit parameter
        foreach($c in $certs){


            $object = New-Object PSObject -Property @{
                subject = $c.Subject.ToString()
                issuer = $c.Issuer.ToString()
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    # Open because most servers do no have DoD issued certs
    $result = 'Open'
    
    # List out the certs on the server    
    $comments = $invReturn | ForEach-Object{"Subject: "+ $_.subject + "`n" + "Issuer: " + $_.issuer + "`n"}
        

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}