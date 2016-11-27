module Network

open System
open System.Net


let macByteArrayToString(buf: System.Byte[]) = 
  sprintf "%02x:%02x:%02x:%02x:%02x:%02x" (buf.[0]) (buf.[1]) (buf.[2]) (buf.[3]) (buf.[4]) (buf.[5])
  

let ipBytesToString(buf: System.Byte[]) = 
  sprintf "%d.%d.%d.%d" (buf.[0]) (buf.[1]) (buf.[2]) (buf.[3])
  

let ipStringToInteger (address) = 
  let addressBytes = IPAddress.Parse(address).GetAddressBytes()
  let addressIntNetworkOrder = BitConverter.ToInt32(addressBytes, 0)
  let addressIntHostOrder = IPAddress.NetworkToHostOrder(addressIntNetworkOrder)
  addressIntHostOrder


let ipStringToIPAddress (ipAddr : string) =
  let mutable ipAddrBin = new IPAddress(0L)
  if IPAddress.TryParse(ipAddr, &ipAddrBin) = false then
    null
  else
    ipAddrBin


let ipIntegerToByteArray (address: Int32) =
  let addressIntNetworkOrder = IPAddress.NetworkToHostOrder(address)
  BitConverter.GetBytes(addressIntNetworkOrder)


let ipByteArrayToString (address: Int32) =
  let addressIntNetworkOrder = IPAddress.NetworkToHostOrder(address)
  BitConverter.GetBytes(addressIntNetworkOrder)

