namespace HttpReverseProxyLib
{
  using System;
  using System.Collections.Generic;
  using System.Net;
  using System.Text.RegularExpressions;


  public class Network
  {

    #region MEMBERS

    private static Network instance;
    private List<Tuple<int, int>> privateNetworks = new List<Tuple<int, int>>();

    #endregion


    #region PROPERTIES

    public static Network Instance { get { return instance ?? (instance = new Network()); } set { } }

    #endregion


    #region PUBLIC

    public Network()
    {
      this.privateNetworks.Add(new Tuple<int, int>(this.GetLongIPAddress("10.0.0.0"), this.GetLongIPAddress("10.255.255.255")));
      this.privateNetworks.Add(new Tuple<int, int>(this.GetLongIPAddress("127.0.0.0"), this.GetLongIPAddress("127.255.255.255")));
      this.privateNetworks.Add(new Tuple<int, int>(this.GetLongIPAddress("172.16.0.0"), this.GetLongIPAddress("172.16.255.255")));
      this.privateNetworks.Add(new Tuple<int, int>(this.GetLongIPAddress("192.168.0.0"), this.GetLongIPAddress("192.168.255.255")));
    }


    public bool HostIsIpAddress(string hostHeader)
    {
      if (string.IsNullOrEmpty(hostHeader) == true)
      {
        return false;
      }

      if (Regex.Match(hostHeader, @"^\s*Host\s*:\s*\d+\.\d+\.\d+\.\d+\s*", RegexOptions.IgnoreCase).Success)
      {
        return true;
      }

      return false;
    }


    public bool IpPartOfPrivateNetwork(string ipAddr)
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

      int ipAddrLong = this.GetLongIPAddress(ipAddr);

      foreach (var tuple in privateNetworks)
      {
        if (ipAddrLong >= tuple.Item1 && ipAddrLong <= tuple.Item2)
        {
          return true;
        }
      }

      return false;
    }


    public int GetLongIPAddress(string ipAddress)
    {
      return IPAddress.NetworkToHostOrder(BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0));
    }

    #endregion


    #region PRIVATE


    private string GetIpFromHostHeader(string hostHeader)
    {
      string ipAddress = string.Empty;
      var matches = Regex.Matches(hostHeader, @"\s*Host\s*:\s*(\d+\.\d+\.\d+\.\d+)\s*", RegexOptions.IgnoreCase);

      if (matches.Count > 0 && matches[0].Groups.Count > 1)
      {
        ipAddress = matches[0].Groups[1].ToString();
      }

      return ipAddress;
    }

    #endregion 

  }
}
