module Pcap

open PcapDotNet.Core


let getPcapDevice (deviceId: string) = 
  LivePacketDevice.AllLocalMachine |> Seq.tryFind (fun elem -> elem.Name.Contains(deviceId))
