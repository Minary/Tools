namespace HttpReverseProxy.Lib
{
  using System;
  using System.Collections;
  using System.Collections.Generic;
  using System.Linq;
  using System.Net;
  using System.Net.NetworkInformation;
  using System.Net.Sockets;


  public class Common
  {

    #region INMPORTS

    [System.Runtime.InteropServices.DllImport("Iphlpapi.dll", EntryPoint = "SendARP")]
    internal static extern Int32 SendArp(Int32 destIpAddress, Int32 srcIpAddress, byte[] macAddress, ref Int32 macAddressLength);

    #endregion


    #region MEMBERS

    private static Hashtable targetMacAddresses = new Hashtable();
    private static List<Tuple<int, int>> privateNetworks = new List<Tuple<int, int>>()
    {
      new Tuple<int, int>(GetLongIPAddress("10.0.0.0"), GetLongIPAddress("10.255.255.255")),
      new Tuple<int, int>(GetLongIPAddress("127.0.0.0"), GetLongIPAddress("127.255.255.255")),
      new Tuple<int, int>(GetLongIPAddress("172.16.0.0"), GetLongIPAddress("172.16.255.255")),
      new Tuple<int, int>(GetLongIPAddress("192.168.0.0"), GetLongIPAddress("192.168.255.255"))
    };

    #endregion


    #region PUBLIC

    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public static string GetLocalIpAddress()
    {
      string retVal = string.Empty;

      foreach (NetworkInterface tmpNetworkIfc in NetworkInterface.GetAllNetworkInterfaces())
      {
        if ((tmpNetworkIfc.NetworkInterfaceType != NetworkInterfaceType.Ethernet &&
             tmpNetworkIfc.NetworkInterfaceType != NetworkInterfaceType.Wireless80211) ||
            tmpNetworkIfc.OperationalStatus != OperationalStatus.Up)
        {
          continue;
        }

        IPInterfaceProperties adapterProperties = tmpNetworkIfc.GetIPProperties();
        GatewayIPAddressInformation gatewayInfo = adapterProperties.GatewayAddresses.FirstOrDefault();

        if (gatewayInfo == null || gatewayInfo.Address == null)
        {
          continue;
        }

        foreach (UnicastIPAddressInformation tmpIpAddr in tmpNetworkIfc.GetIPProperties().UnicastAddresses)
        {
          if (tmpIpAddr.Address.AddressFamily == AddressFamily.InterNetwork)
          {
            retVal = tmpIpAddr.Address.ToString();
            break;
          }
        }
      }

      return retVal;
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="ipAddr"></param>
    /// <returns></returns>
    public static int ConvertIpToInt32(IPAddress ipAddr)
    {
      byte[] byteAddress = ipAddr.GetAddressBytes();
      return BitConverter.ToInt32(byteAddress, 0);
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="clientIp"></param>
    /// <returns></returns>
    public static string GetMacFromNetworkComputer(string clientIp)
    {
      string retVal = string.Empty;
      int convertedIpAddr = 0;
      byte[] macArray;
      int byteArrayLen = 0;
      int arpReply = 0;
      IPAddress ipAddress = null;

      // First check the local cache if IP/MAC entry exists.
      if (targetMacAddresses.ContainsKey(clientIp))
      {
        return targetMacAddresses[clientIp].ToString();
      }

      // Target MAC is not in local cache. Send ARP request.
      ipAddress = IPAddress.Parse(clientIp);

      if (ipAddress.AddressFamily != AddressFamily.InterNetwork)
      {
        throw new ArgumentException("The remote system only supports IPv4 addresses");
      }

      convertedIpAddr = Common.ConvertIpToInt32(ipAddress);
      macArray = new byte[6]; // 48 bit
      byteArrayLen = macArray.Length;

      if ((arpReply = SendArp(convertedIpAddr, 0, macArray, ref byteArrayLen)) != 0)
      {
        throw new Exception(string.Format("Error no. {0} occured while resolving MAC address of system {1}", arpReply, clientIp));
      }

      // return the MAC address in a PhysicalAddress format
      for (int i = 0; i < macArray.Length; i++)
      {
        retVal += string.Format("{0}", macArray[i].ToString("X2"));
        retVal += (i != macArray.Length - 1) ? "-" : string.Empty;
      }

      // Add IP/MAC to cache.
      targetMacAddresses.Add(clientIp, retVal);

      return retVal;
    }


    public static bool IsIpPartOfPrivateNetwork(string ipAddr)
    {
      IPAddress ipAddrObj;

      if (string.IsNullOrEmpty(ipAddr) == true)
      {
        return false;
      }

      if (IPAddress.TryParse(ipAddr, out ipAddrObj) == false)
      {
        return false;
      }

      int ipAddrLong = GetLongIPAddress(ipAddr);
      foreach (var tuple in privateNetworks)
      {
        if (ipAddrLong >= tuple.Item1 && ipAddrLong <= tuple.Item2)
        {
          return true;
        }
      }

      return false;
    }

    #endregion


    #region PRIVATE

    private static int GetLongIPAddress(string ipAddress)
    {
      return IPAddress.NetworkToHostOrder(BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0));
    }

    #endregion
  }
}