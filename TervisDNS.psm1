function Get-TervisDNSMXMailServer {
    Resolve-DnsName -Name tervis.com -Type MX -Server 8.8.8.8 | 
    sort prefernce -Descending | 
    select -First 1 -ExpandProperty NameExchange
}

function Remove-TervisDNSRecordsforVM{
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [switch]$PassThru
    )
    $NodeToDelete = $VM.Name
    $DNSServer = "inf-dc1"
    $ZoneName = "tervis.prv"
    $NodeDNS = $null
    $NodeDNSARecord = Get-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -Node $NodeToDelete -RRType A -ErrorAction SilentlyContinue
    $NodeDNSCnameRecord = Get-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -RRType CName -ErrorAction SilentlyContinue | where { $_.recorddata.hostnamealias -Match $nodetodelete}
    if($NodeDNSARecord){Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -InputObject $NodeDNSARecord -Confirm}
    if($NodeDNSCnameRecord){Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -InputObject $NodeDNSCnameRecord -Confirm}

    if($PassThru) {$VM}
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
