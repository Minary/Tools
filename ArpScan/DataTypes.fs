module DataTypes

open System


type ScanParams = 
  struct
      val InterfaceId: string
      val StartIpStr: string
      val StopIpStr: string
      val mutable LocalIpStr: string
      val mutable LocalIpBytes: System.Byte[]
      val mutable LocalMacStr: string
      val mutable LocalMacBytes: System.Byte[]
      new(interfaceId, startIpStr, stopIpStr) = 
        { InterfaceId = interfaceId; 
          StartIpStr = startIpStr;
          StopIpStr = stopIpStr;
          LocalIpStr = String.Empty;
          LocalIpBytes = null;
          LocalMacStr = String.Empty;
          LocalMacBytes = null
          }
  end

  
type SystemFound = 
  struct
      val MacAddress: string
      val IpAddress: string
      new(macAddress, ipAddress) = 
        { MacAddress = macAddress; 
          IpAddress = ipAddress
        }
  end