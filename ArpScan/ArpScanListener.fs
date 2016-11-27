module ArpScanListener

open DataTypes
open Network
open Pcap
open PcapDotNet.Core
open PcapDotNet.Core.Extensions
open PcapDotNet.Packets
open PcapDotNet.Packets.Arp
open PcapDotNet.Packets.Ethernet
open System
open System.Linq
open System.Net
open System.Net.NetworkInformation

let systemsFound = new System.Collections.Generic.Dictionary<string, SystemFound>()


let stringify (dataBytes: byte[]) =
  let mutable dataString = String.Empty
  for elem in dataBytes do
    let asciiVal : int = System.Convert.ToInt32(elem)
    if 31 < asciiVal  && asciiVal < 127 then
      dataString <- dataString + (sprintf "%A" asciiVal)
    else 
      dataString <- dataString + "."
  dataString


let packetHandler(packet: Packet) =
  if packet <> null && packet.Length > 0  && packet.IsValid &&
     packet.Ethernet.EtherType = EthernetType.Arp &&
     packet.Ethernet.Arp.Operation = ArpOperation.Reply then 
        let senderMac = Network.macByteArrayToString(packet.Ethernet.Arp.SenderHardwareAddress.ToArray())
        if systemsFound.ContainsKey(senderMac) = false then
          let senderIp = Network.ipBytesToString(packet.Ethernet.Arp.SenderProtocolAddress.ToArray())
          let newSystem : SystemFound = new SystemFound(senderMac, senderIp)
          systemsFound.Add(senderMac, newSystem)
          printfn "<arp>\n  <type>reply</type>\n  <ip>%s</ip>\n  <mac>%s</mac>\n</arp>\n<EOF>" senderIp senderMac


let readArpPackets (scanParams: ScanParams) =
  let selectedDevice = Pcap.getPcapDevice(scanParams.InterfaceId)
  let communicator = selectedDevice.Value.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1)
  communicator.SetFilter(communicator.CreateFilter("arp and arp[6:2] = 2"))
  
  let mutable packet = null
  let mutable result = null
  while true do
    match communicator.ReceivePacket(&packet) with
    | PacketCommunicatorReceiveResult.Timeout -> ()
    | PacketCommunicatorReceiveResult.Ok      -> packetHandler(packet)
    |_                                        -> raise (new Exception ("Fatal error occurred in Pcap"))



