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

    private static CacheHsts instance;
    private Dictionary<string, HstsRecord> cache = new Dictionary<string, HstsRecord>();

    #endregion


    #region PROPERTIES

    public static CacheHsts Instance { get { return instance ?? (instance = new CacheHsts()); } set { } }
    public Dictionary<string, HstsRecord> HstsCache { get { return this.cache; } set { } }

    #endregion


    #region PUBLIC METHODS

    /// <summary>
    /// Initializes a new instance of the <see cref="CacheHsts"/> class.
    ///
    /// </summary>
    private CacheHsts()
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
      if (this.cache.ContainsKey(host))
      {
        return;
      }

      Logging.Instance.LogMessage("SslStrip.CacheHsts.AddElement", ProxyProtocol.Undefined, Loglevel.DEBUG, "Cache.AddElement(): host => {0}", host);

      HstsRecord tmpHost = new HstsRecord(host);
      this.cache.Add(host, tmpHost);
    }


    /// <summary>
    ///
    /// </summary>
    public void EnumerateCache()
    {
      foreach (string tmpKey in this.cache.Keys)
      {
        Logging.Instance.LogMessage("SslStrip.CacheHsts.EnumerateCache", ProxyProtocol.Undefined, Loglevel.DEBUG, "EnumerateCache(): host:\"{0}\"", tmpKey);
      }
    }


    /// <summary>
    ///
    /// </summary>
    public void ResetCache()
    {
      if (this.cache != null)
      {
        this.cache.Clear();
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

      if (this.cache.ContainsKey(host))
      {
        return this.cache.Remove(host);
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

      if (!this.cache.ContainsKey(host))
      {
        return null;
      }

      return this.cache[host];
    }



    /// <summary>
    ///
    /// </summary>
    /// <param name="host"></param>
    /// <returns></returns>
    public bool NeedsRequestBeMapped(string host)
    {
      if (!string.IsNullOrEmpty(host) && !string.IsNullOrWhiteSpace(host) && this.cache.ContainsKey(host))
      {
        return true;
      }

      return false;
    }

    #endregion

  }
}