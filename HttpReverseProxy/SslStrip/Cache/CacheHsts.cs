namespace HttpReverseProxy.Plugin.SslStrip.Cache
{
  using HttpReverseProxy.Plugin.SslStrip.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.Collections.Generic;


  public class CacheHsts
  {

    #region PROPERTIES
    
    public Dictionary<string, HstsRecord> HstsCache { get; set; } = new Dictionary<string, HstsRecord>();

    #endregion


    #region PUBLIC METHODS

    /// <summary>
    ///
    /// </summary>
    /// <param name="host"></param>
    public void AddElement(string host)
    {
      // host checks
      if (string.IsNullOrEmpty(host) || string.IsNullOrWhiteSpace(host))
      {
        throw new Exception("Something is wrong with the host name");
      }

      // Return if element already exists
      if (HstsCache.ContainsKey(host))
      {
        return;
      }

      Logging.Instance.LogMessage("SslStrip.CacheHsts.AddElement", ProxyProtocol.Undefined, Loglevel.Debug, "Cache.AddElement(): host => {0}", host);

      HstsRecord tmpHost = new HstsRecord(host);
      HstsCache.Add(host, tmpHost);
    }


    /// <summary>
    ///
    /// </summary>
    public void EnumerateCache()
    {
      foreach (string tmpKey in HstsCache.Keys)
      {
        Logging.Instance.LogMessage("SslStrip.CacheHsts.EnumerateCache", ProxyProtocol.Undefined, Loglevel.Debug, "EnumerateCache(): host:\"{0}\"", tmpKey);
      }
    }


    /// <summary>
    ///
    /// </summary>
    public void ResetCache()
    {
      HstsCache.Clear();
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="host"></param>
    /// <returns></returns>
    public bool DeleteElement(string host)
    {
      if (string.IsNullOrEmpty(host) || string.IsNullOrWhiteSpace(host))
      {
        throw new Exception("Something is wrong with the host name");
      }

      if (HstsCache.ContainsKey(host))
      {
        return HstsCache.Remove(host);
      }

      return false;
    }



    /// <summary>
    ///
    /// </summary>
    /// <param name="host"></param>
    /// <returns></returns>
    public HstsRecord GetElement(string host)
    {
      if (string.IsNullOrEmpty(host) || string.IsNullOrWhiteSpace(host))
      {
        throw new Exception("Something is wrong with the host name");
      }

      if (!HstsCache.ContainsKey(host))
      {
        return null;
      }

      return HstsCache[host];
    }



    /// <summary>
    ///
    /// </summary>
    /// <param name="host"></param>
    /// <returns></returns>
    public bool NeedsRequestBeMapped(string host)
    {
      if (!string.IsNullOrEmpty(host) && 
          !string.IsNullOrWhiteSpace(host) && 
          HstsCache.ContainsKey(host))
      {
        return true;
      }

      return false;
    }

    #endregion

  }
}