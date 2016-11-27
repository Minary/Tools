module Program

open ArpScanListener
open ArpScanSender
open DataTypes
open NetworkAdapter
open System;
open System.Runtime.InteropServices
open System.Text
open System.ComponentModel
open System.Threading


let printUsage () = 
  let appName = AppDomain.CurrentDomain.FriendlyName
  printfn "Usage %s [-h|-l|-d ifc]" appName
  printfn "\n%s -s {IFCID} STARTIP STOPIP\t Start ARP scan on interface IFCID, IP range from STOPIP to STOPIP" appName
  printfn "%s -h\t\t\t Show this help listing here" appName
  printfn "%s -l\t\t\t List all active interfaces" appName
  

let determineScanParams(interfaceId: string, startIpStr: string, stopIpStr: string) =
  let mutable scanParams = ScanParams(interfaceId, startIpStr, stopIpStr)
  scanParams.LocalIpStr <- getIpAddressStringFromInterface(interfaceId)
  scanParams.LocalIpBytes <- getIpAddressBytesFromInterface(interfaceId)
  scanParams.LocalMacStr <- getMacAddressStringFromInterface(interfaceId)
  scanParams.LocalMacBytes <- getMacAddressBytesFromInterface(interfaceId)
  scanParams


let handleArpScan(scanParams : ScanParams) =
  let work = new BackgroundWorker()
  do work.DoWork.Add(fun args -> ArpScanListener.readArpPackets(scanParams))
  do work.RunWorkerAsync()

  try
    for counter in 1..3 do
      ArpScanSender.scanNetwork(scanParams)
      Thread.Sleep(200)
  with ex ->
    printfn "Exception: %s" ex.Message


[<EntryPoint>]
let main (args) =
  if (args.Length = 4 && args.[0].ToLower() = "-s") then 
    let scanParams = determineScanParams(args.[1], args.[2], args.[3])
    handleArpScan(scanParams)
  elif (args.Length = 1 && args.[0].ToLower() = "-l") then
    NetworkAdapter.printInterfaceDetails() 
  else
    printUsage()
  0