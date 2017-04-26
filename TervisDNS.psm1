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
    if($NodeDNSARecord){Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -InputObject $NodeDNSARecord -Force}
    if($NodeDNSCnameRecord){Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -InputObject $NodeDNSCnameRecord -Force}

    if($PassThru) {$VM}
}
