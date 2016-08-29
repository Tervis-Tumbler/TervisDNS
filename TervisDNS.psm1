function Get-TervisDNSMXMailServer {
    Resolve-DnsName -Name tervis.com -Type MX -Server 8.8.8.8 | 
    sort prefernce -Descending | 
    select -First 1 -ExpandProperty NameExchange
}