module ArpScanSender

open DataTypes
open Network
open Pcap
open PcapDotNet.Core
open PcapDotNet.Core.Extensions
open PcapDotNet.Packets
open PcapDotNet.Packets.Arp
open PcapDotNet.Packets.Ethernet
open System
open System.Collections.ObjectModel
open System.Net
open System.Net.NetworkInformation



let buildArpWhoHasPacket (scanParams : ScanParams, remoteIpInt: Int32) =
  let ethernetPacket : EthernetLayer = new EthernetLayer()
  ethernetPacket.EtherType <- EthernetType.Arp
  ethernetPacket.Source <- new MacAddress(scanParams.LocalMacStr)
  ethernetPacket.Destination <- new MacAddress("ff:ff:ff:ff:ff:ff")

  let arpPacket : ArpLayer = new ArpLayer()
  arpPacket.ProtocolType <- EthernetType.IpV4
  arpPacket.Operation <- ArpOperation.Request
  arpPacket.SenderHardwareAddress <- scanParams.LocalMacBytes |> ReadOnlyCollection
  arpPacket.SenderProtocolAddress <- scanParams.LocalIpBytes |> ReadOnlyCollection 
  
  arpPacket.TargetHardwareAddress <- Array.init 6 (fun i -> byte(0)) |> ReadOnlyCollection
  arpPacket.TargetProtocolAddress <- Network.ipIntegerToByteArray(remoteIpInt) |> ReadOnlyCollection
  
  let packet = new PacketBuilder(ethernetPacket, arpPacket)
  packet.Build(DateTime.Now)


let scanNetwork(scanParams: ScanParams) =
  let selectedDevice = Pcap.getPcapDevice(scanParams.InterfaceId)
  let communicator = selectedDevice.Value.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1)
  let startIpInt = Network.ipStringToInteger(scanParams.StartIpStr)
  let stopIpInt = ipStringToInteger(scanParams.StopIpStr)

  if startIpInt > stopIpInt then
    raise (new Exception("The start IP address is greater than the end address"))
  
  for tmpIpInt in seq { startIpInt .. stopIpInt} do
    try
      let arpPacket = buildArpWhoHasPacket(scanParams, tmpIpInt)
      communicator.SendPacket(arpPacket)
    with ex -> printfn "Exception: %s\n%s" ex.Message ex.StackTrace
    System.Threading.Thread.Sleep(5)

