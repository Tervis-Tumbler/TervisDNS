function Get-TervisDNSMXMailServer {
    Resolve-DnsName -Name tervis.com -Type MX -Server 8.8.8.8 | 
    sort prefernce -Descending | 
    select -First 1 -ExpandProperty NameExchange
}

function Remove-TervisDNSRecord {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$ComputerName
    )
    begin {
        $DomainController = Get-ADDomainController        
        $DNSServerName = $DomainController.HostName
        $ZoneName = $DomainController.Domain
    }
    process {
        Get-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServerName -Node $ComputerName -RRType A -ErrorAction SilentlyContinue |
        Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServerName

        Get-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServerName -RRType CName -ErrorAction SilentlyContinue | 
        where { $_.recorddata.hostnamealias -Match $ComputerName } |
        Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServerName
    }
}

function Set-TervisDnsServerResourceRecordOldToNewIPv4 {
    param (
        $OldIPAddress,
        $NewIPAddress
    )
    $DnsServerZones = Get-DnsServerZone | 
    Where { -not $_.IsReverseLookupZone }
 
    $Records = foreach ($Zone in $DnsServerZones) {
        $Zone |
        Get-DnsServerResourceRecord -RRType A |
        Add-Member -MemberType NoteProperty -Name ZoneName -Value $Zone.ZoneName -PassThru |
        where { $_.RecordData.IPv4Address.IPAddressToString -EQ $OldIPAddress }
    }

    $Records | Update-TervisDnsServerAResourceRecordIPAddress -IPAddress $NewIPAddress
}

function Update-TervisDnsServerAResourceRecordIPAddress {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$ResourceRecord,
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ZoneName,
        [Switch]$PassThru
    )
    process {
        $NewResourceRecord = $ResourceRecord.Clone()
        $NewResourceRecord.RecordData.IPv4Address = $IPAddress
        Set-DnsServerResourceRecord -NewInputObject $NewResourceRecord -OldInputObject $ResourceRecord -ZoneName $ZoneName -PassThru:$PassThru
    }
}

function Update-ExternalServicesInDNS {
    begin {
        $WebRequest = Invoke-WebRequest "http://api.ipify.org/"
        [string]$FinalIPAddress = $WebRequest.content
        Connect-ToAzure -Subscription Production/Infrastructure
    }

    process {
        $Changes = @()
        $CurrentAutoDiscover = Get-AzureRmDnsRecordSet -ZoneName tervis.com -Name autodiscover -ResourceGroupName Infrastructure -RecordType CNAME
        $CurrentAutoDiscoverCname = $CurrentAutoDiscover | 
            Select -ExpandProperty Records | 
            Select -ExpandProperty Cname
        if (($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') -and (-NOT ($CurrentAutoDiscoverCname -match "hermes.cogent.tervis.com"))) {
            $CurrentAutoDiscover | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name autodiscover -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "hermes.cogent.tervis.com")
            $Changes += "autodiscover.tervis.com was pointed to hermes.cogent.tervis.com. `r"
        } elseif (($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') -and (-NOT ($CurrentAutoDiscoverCname -match "hermes.fios150.tervis.com"))) {
            $CurrentAutoDiscover | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name autodiscover -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "hermes.fios150.tervis.com")
            $Changes += "autodiscover.tervis.com was pointed to hermes.fios150.tervis.com. `r"
        }

        $CurrentCiscoVPN = Get-AzureRmDnsRecordSet -ZoneName tervis.com -Name ciscovpn -ResourceGroupName Infrastructure -RecordType CNAME
        $CurrentCiscoVpnCname = $CurrentCiscoVPN | 
            Select -ExpandProperty Records | 
            Select -ExpandProperty Cname
        if (($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') -and (-NOT ($CurrentCiscoVpnCname -match "ciscovpn.cogent.tervis.com"))) {
            $CurrentCiscoVPN | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name ciscovpn -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "ciscovpn.cogent.tervis.com")
            $Changes += "ciscovpn.tervis.com was pointed to hermes.cogent.tervis.com. `r"
        } elseif (($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') -and (-NOT ($CurrentCiscoVpnCname -match "ciscovpn.fios150.tervis.com"))) {
            $CurrentCiscoVPN | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name ciscovpn -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "ciscovpn.fios150.tervis.com")
            $Changes += "ciscovpn.tervis.com was pointed to hermes.fios150.tervis.com. `r"
        } elseif (($FinalIPAddress -eq '96.243.198.58' -or $FinalIPAddress -eq '96.243.198.60') -and (-NOT ($CurrentCiscoVpnCname -match "ciscovpn.fios25.tervis.com"))) {
            $CurrentCiscoVPN | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name ciscovpn -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "ciscovpn.fios25.tervis.com")
            $Changes += "ciscovpn.tervis.com was pointed to hermes.fios25.tervis.com. `r"
        }

        $CurrentDemandwareFtp = Get-AzureRmDnsRecordSet -ZoneName tervis.com -Name demandwareftp -ResourceGroupName Infrastructure -RecordType CNAME
        $CurrentDemandwareFtpCname = $CurrentDemandwareFtp | 
            Select -ExpandProperty Records | 
            Select -ExpandProperty Cname
        if (($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') -and (-NOT ($CurrentDemandwareFtpCname -match "demandwareftp.cogent.tervis.com"))) {
            $CurrentDemandwareFtp | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name demandwareftp -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "demandwareftp.cogent.tervis.com")
            $Changes += "demandwareftp.tervis.com was pointed to demandwareftp.cogent.tervis.com. `r"
        } elseif (($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') -and (-NOT ($CurrentDemandwareFtpCname -match "demandwareftp.fios150.tervis.com"))) {
            $CurrentDemandwareFtp | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name demandwareftp -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "demandwareftp.fios150.tervis.com")
            $Changes += "demandwareftp.tervis.com was pointed to demandwareftp.fios150.tervis.com. `r"
        }

        $CurrentHermes = Get-AzureRmDnsRecordSet -ZoneName tervis.com -Name hermes -ResourceGroupName Infrastructure -RecordType A
        $CurrentHermesIpv4Address = $CurrentHermes | 
            Select -ExpandProperty Records | 
            Select -ExpandProperty Ipv4Address
        if (($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') -and (-NOT ($CurrentHermesIpv4Address -eq "38.95.4.139"))) {
            Add-AzureRmDnsRecordConfig -IPv4Address "38.95.4.139" -RecordSet $CurrentHermes
            Remove-AzureRmDnsRecordConfig -IPv4Address $CurrentHermesIpv4Address -RecordSet $CurrentHermes
            $Changes += "hermes.tervis.com was set to 38.95.4.139. `r"
        } elseif (($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') -and (-NOT ($CurrentHermesIpv4Address -eq "100.3.102.5"))) {
            Add-AzureRmDnsRecordConfig -IPv4Address "100.3.102.5" -RecordSet $CurrentHermes
            Remove-AzureRmDnsRecordConfig -IPv4Address $CurrentHermesIpv4Address -RecordSet $CurrentHermes
            $Changes += "hermes.tervis.com was set to 100.3.102.5. `r"
        }

        $CurrentMizerFtp = Get-AzureRmDnsRecordSet -ZoneName tervis.com -Name mizerftp -ResourceGroupName Infrastructure -RecordType CNAME
        $CurrentMizerFtpCname = $CurrentMizerFtp | 
            Select -ExpandProperty Records | 
            Select -ExpandProperty Cname
        if (($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') -and (-NOT ($CurrentMizerFtpCname -match "mizerftp.cogent.tervis.com"))) {
            $CurrentMizerFtp | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name mizerftp -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "mizerftp.cogent.tervis.com")
            $Changes += "mizerftp.tervis.com was pointed to mizerftp.cogent.tervis.com. `r"
        } elseif (($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') -and (-NOT ($CurrentMizerFtpCname -match "mizerftp.fios150.tervis.com"))) {
            $CurrentMizerFtp | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name mizerftp -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "mizerftp.fios150.tervis.com")
            $Changes += "mizerftp.tervis.com was pointed to mizerftp.fios150.tervis.com. `r"
        }

        $CurrentRdGateway = Get-AzureRmDnsRecordSet -ZoneName tervis.com -Name rdgateway -ResourceGroupName Infrastructure -RecordType CNAME
        $CurrentRdGatewayCname = $CurrentRdGateway | 
            Select -ExpandProperty Records | 
            Select -ExpandProperty Cname
        if (($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') -and (-NOT ($CurrentRdGatewayCname -match "rdgateway.cogent.tervis.com"))) {
            $CurrentRdGateway | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name rdgateway -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "rdgateway.cogent.tervis.com")
            $Changes += "rdgateway.tervis.com was pointed to rdgateway.cogent.tervis.com. `r"
        } elseif (($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') -and (-NOT ($CurrentRdGatewayCname -match "rdgateway.fios150.tervis.com"))) {
            $CurrentRdGateway | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name rdgateway -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "rdgateway.fios150.tervis.com")
            $Changes += "rdgateway.tervis.com was pointed to rdgateway.fios150.tervis.com. `r"
        }

        $CurrentScene7Ftp = Get-AzureRmDnsRecordSet -ZoneName tervis.com -Name scene7ftp -ResourceGroupName Infrastructure -RecordType CNAME
        $CurrentScene7FtpCname = $CurrentScene7Ftp | 
            Select -ExpandProperty Records | 
            Select -ExpandProperty Cname
        if (($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') -and (-NOT ($CurrentScene7FtpCname -match "scene7ftp.cogent.tervis.com"))) {
            $CurrentScene7Ftp | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name scene7ftp -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "scene7ftp.cogent.tervis.com")
            $Changes += "scene7ftp.tervis.com was pointed to scene7ftp.cogent.tervis.com. `r"
        } elseif (($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') -and (-NOT ($CurrentScene7FtpCname -match "scene7ftp.fios150.tervis.com"))) {
            $CurrentScene7Ftp | Remove-AzureRmDnsRecordSet
            New-AzureRmDnsRecordSet -Name scene7ftp -RecordType CNAME -ZoneName tervis.com -ResourceGroupName Infrastructure -Ttl 300 -DnsRecords (New-AzureRmDnsRecordConfig -Cname "scene7ftp.fios150.tervis.com")
            $Changes += "scene7ftp.tervis.com was pointed to scene7ftp.fios150.tervis.com. `r"
        }
    }

    end {
        if ($FinalIPAddress -eq '38.95.4.130' -or $FinalIPAddress -eq '38.95.4.131') {
            if (!($Changes -eq '')) {
                    $body = 'The failover script running on DNS1 detected an ISP change. ' + `
                'The current ISP is Cogent. Below are the settings that were updated by Update-ExternalServicesInDns.ps1 ' + "`n`n" + `
                $Changes
                send-mailmessage -to "SystemsTeam@tervis.com" `
                -from "mailerdaemon@tervis.com" `
                -subject "Failover Script: External services moved to the Cogent ISP" `
                -body $body `
                -smtpServer hermes.tervis.com
            }
        } elseif ($FinalIPAddress -eq '100.3.102.2' -or $FinalIPAddress -eq '100.3.102.3') {
            if (!($Changes -eq '')) {
                    $body = 'The failover script running on DNS1 detected an ISP change. ' + `
                'The current ISP is Fios150. Below are the settings that were updated by Update-ExternalServicesInDns.ps1 ' + "`n`n" + `
                $Changes
                send-mailmessage -to "SystemsTeam@tervis.com" `
                -from "mailerdaemon@tervis.com" `
                -subject "Failover Script: External services moved to the Fios150 ISP" `
                -body $body `
                -smtpServer hermes.tervis.com
            }
        } else {
            $body = 'The failover script Update-ExternalServicesInDNS running on DNS1 was not able to determine the public IP address, ' + `
            'or the response was not a defined public IP. This could just be a timeout, but if it happens a lot it may need to be looked at. ' + `
            'Below is the results of the public IP address query. ' + `
            $FinalIPAddress
            send-mailmessage -to "WindowsServerApplicationsAdministrator@tervis.com" `
            -from "mailerdaemon@tervis.com" `
            -subject "Failover Script: Cannot determine public IP address" `
            -body $body `
            -smtpServer hermes.tervis.com
        }
    }
}

function Install-UpdateExternalServicesInDNS {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $ScheduledTaskCredential = New-Object System.Management.Automation.PSCredential (Get-PasswordstateCredential -PasswordID 259)
        $Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $Argument = '-Command Update-ExternalServicesInDNS'
    }
    process {
        $CimSession = New-CimSession -ComputerName $ComputerName
        If (-NOT (Get-ScheduledTask -TaskName Update-ExternalServicesInDNS -CimSession $CimSession -ErrorAction SilentlyContinue)) {
            Install-TervisScheduledTask -Credential $ScheduledTaskCredential -TaskName Update-ExternalServicesInDNS -Execute $Execute -Argument $Argument -RepetitionIntervalName EveryDayEver5Minutes -ComputerName $ComputerName
        }
    }
}
