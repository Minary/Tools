module NetworkAdapter

open Network
open System
open System.Net.NetworkInformation


let dnsServersStr(dnsServerCollection : IPAddressCollection) =
  let mutable dnsServers = String.Empty
  for dnsServer in dnsServerCollection do
    dnsServers <- dnsServers + " " + (dnsServer.ToString())
  dnsServers.Trim()


let gatewayServersStr(gatewayCollection : GatewayIPAddressInformationCollection) = 
  let mutable gateways = String.Empty
  for gateway in gatewayCollection do
    gateways <- gateways + " " + (gateway.Address.ToString())
  gateways.Trim()


let unicastAddressesStr(unicastAddressCollection : UnicastIPAddressInformationCollection) = 
  let mutable unicastAddressesStr = String.Empty
  for unicastAddress in unicastAddressCollection do
    unicastAddressesStr <- unicastAddressesStr + " " + (unicastAddress.Address.ToString())
  unicastAddressesStr.Trim()


let printInterfaceDetail (nic : NetworkInterface) = 
  printfn "\n%-20s = %s" "Id" nic.Id
  printfn "%-20s = %s" "Type" (nic.NetworkInterfaceType.ToString())
  printfn "%-20s = %s" "Status" (nic.OperationalStatus.ToString())
  printfn "%-20s = %s" "MAC address" (Network.macByteArrayToString(nic.GetPhysicalAddress().GetAddressBytes()))
  printfn "%-20s = %s" "IP address(es)" (unicastAddressesStr(nic.GetIPProperties().UnicastAddresses))
  printfn "%-20s = %s" "Gateways" (gatewayServersStr(nic.GetIPProperties().GatewayAddresses))
  printfn "%-20s = %s" "Description" nic.Description
  printfn "%-20s = %s" "DNS servers" (dnsServersStr(nic.GetIPProperties().DnsAddresses))  
  

let printInterfaceDetails () = 
  for nic in NetworkInterface.GetAllNetworkInterfaces() do
    if (nic.OperationalStatus = OperationalStatus.Up && 
        (nic.NetworkInterfaceType = NetworkInterfaceType.Ethernet || 
         nic.NetworkInterfaceType = NetworkInterfaceType.Wireless80211)) then        
        printInterfaceDetail nic
        

let getIpAddressStringFromInterface (deviceId: string) = 
  let ifc = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces() |> Seq.tryFind (fun elem -> elem.Id.Contains(deviceId))
  let ipAddresses = ifc.Value.GetIPProperties().UnicastAddresses |> Seq.tryFind(fun elem -> elem.Address.IsIPv6LinkLocal = false)
  (ipAddresses.Value.Address.ToString())


let getIpAddressBytesFromInterface (deviceId: string) = 
  let ifc = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces() |> Seq.tryFind (fun elem -> elem.Id.Contains(deviceId))
  let ipAddresses = ifc.Value.GetIPProperties().UnicastAddresses |> Seq.tryFind(fun elem -> elem.Address.IsIPv6LinkLocal = false)
  ipAddresses.Value.Address.GetAddressBytes()


let getMacAddressStringFromInterface (deviceId: string) = 
  let ifc = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces() |> Seq.tryFind (fun elem -> elem.Id.Contains(deviceId))
  let macAddressBytes = ifc.Value.GetPhysicalAddress().GetAddressBytes()
  macByteArrayToString(macAddressBytes)

  
let getMacAddressBytesFromInterface (deviceId: string) = 
  let ifc = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces() |> Seq.tryFind (fun elem -> elem.Id.Contains(deviceId))
  ifc.Value.GetPhysicalAddress().GetAddressBytes()
