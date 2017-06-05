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
