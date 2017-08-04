namespace HttpReverseProxy.Plugin.SslStrip.Cache
{
  using HttpReverseProxy.Plugin.SslStrip.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.Collections.Generic;


  public class CacheHsts
  {

    #region MEMBER
    
    private static Dictionary<string, HstsRecord> cache = new Dictionary<string, HstsRecord>();

    #endregion


    #region PROPERTIES
    
    public Dictionary<string, HstsRecord> HstsCache { get { return cache; } set { } }

    #endregion


    #region PUBLIC METHODS

    /// <summary>
    /// Initializes a new instance of the <see cref="CacheHsts"/> class.
    ///
    /// </summary>
    public CacheHsts()
    {
    }



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
      if (cache.ContainsKey(host))
      {
        return;
      }

      Logging.Instance.LogMessage("SslStrip.CacheHsts.AddElement", ProxyProtocol.Undefined, Loglevel.Debug, "Cache.AddElement(): host => {0}", host);

      HstsRecord tmpHost = new HstsRecord(host);
      cache.Add(host, tmpHost);
    }


    /// <summary>
    ///
    /// </summary>
    public void EnumerateCache()
    {
      foreach (string tmpKey in cache.Keys)
      {
        Logging.Instance.LogMessage("SslStrip.CacheHsts.EnumerateCache", ProxyProtocol.Undefined, Loglevel.Debug, "EnumerateCache(): host:\"{0}\"", tmpKey);
      }
    }


    /// <summary>
    ///
    /// </summary>
    public void ResetCache()
    {
      if (cache != null)
      {
        cache.Clear();
      }
      else
      {
        cache = new Dictionary<string, HstsRecord>();
      }
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

      if (cache.ContainsKey(host))
      {
        return cache.Remove(host);
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

      if (!cache.ContainsKey(host))
      {
        return null;
      }

      return cache[host];
    }



    /// <summary>
    ///
    /// </summary>
    /// <param name="host"></param>
    /// <returns></returns>
    public bool NeedsRequestBeMapped(string host)
    {
      if (!string.IsNullOrEmpty(host) && !string.IsNullOrWhiteSpace(host) && cache.ContainsKey(host))
      {
        return true;
      }

      return false;
    }

    #endregion

  }
}