namespace HttpReverseProxy.Plugin.SslStrip.Cache
{
  using HttpReverseProxy.Plugin.SslStrip.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.Collections.Generic;
  using System.Text.RegularExpressions;

  public class CacheSslStrip
  {

    #region MEMBERS

    private static CacheSslStrip instance;
    private Dictionary<string, HostRecord> cache = new Dictionary<string, HostRecord>();

    #endregion


    #region PROPERTIES

    public static CacheSslStrip Instance { get { return instance ?? (instance = new CacheSslStrip()); } set { } }
    public Dictionary<string, HostRecord> SslStripCache { get { return this.cache; } set { } }

    #endregion


    #region PUBLIC

    /// <summary>
    ///
    /// </summary>
    /// <param name="keyLocation"></param>
    /// <param name="valueLocation"></param>
    /// <param name="hstsEnabled"></param>
    public void AddElement(string id, string keyLocation, string valueLocation)
    {
      // Key value checks
      if (!Uri.IsWellFormedUriString(keyLocation, UriKind.Absolute))
      {
        throw new Exception("Key Uri is not well formed");
      }

      Uri tmpUriKey = new Uri(keyLocation);
      if (tmpUriKey == null || !Regex.Match(tmpUriKey.Scheme, @"^https?$").Success)
      {
        throw new Exception("Key Uri is not well formed");
      }

      // Value URI checks
      if (!Uri.IsWellFormedUriString(valueLocation, UriKind.Absolute))
      {
        throw new Exception("Value Uri is not well formed");
      }

      Uri tmpUriValue = new Uri(valueLocation);
      if (tmpUriValue == null || !Regex.Match(tmpUriValue.Scheme, @"^https?$").Success)
      {
        throw new Exception("Value Uri is not well formed");
      }

      if (this.NeedsRequestBeMapped(keyLocation))
      {
        throw new Exception("Key was already added to the cache");
      }

      Logging.Instance.LogMessage(id, ProxyProtocol.Undefined, Loglevel.Debug, "CacheSslStrip.Cache.AddElement(): {0} => {1}", keyLocation, valueLocation);

      HostRecord tmpHost = new HostRecord("GET", ProxyProtocol.Https, tmpUriValue.Host, tmpUriValue.PathAndQuery);
      this.cache.Add(keyLocation, tmpHost);
    }

    /// <summary>
    ///
    /// </summary>
    public void EnumerateCache()
    {
      foreach (string tmpKey in this.cache.Keys)
      {
        Logging.Instance.LogMessage("SslStrip.CacheSslStrip.EnumerateCache", ProxyProtocol.Undefined, Loglevel.Debug, "Cache.EnumerateCache(): Key:{0} Value:{1}, Counter:{2}", tmpKey, this.cache[tmpKey].Url, cache[tmpKey].Counter);
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
    /// <param name="urlKey"></param>
    /// <returns></returns>
    public bool DeleteElement(string urlKey)
    {
      if (!Uri.IsWellFormedUriString(urlKey, UriKind.Absolute))
      {
        throw new Exception("Key Uri is not well formed");
      }

      if (this.cache.ContainsKey(urlKey))
      {
        return this.cache.Remove(urlKey);
      }

      return false;
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="url"></param>
    /// <returns></returns>
    public HostRecord GetElement(string urlKey)
    {
      if (!Uri.IsWellFormedUriString(urlKey, UriKind.Absolute))
      {
        throw new Exception("The Url is malformed");
      }

      if (!this.cache.ContainsKey(urlKey))
      {
        return null;
      }

      return this.cache[urlKey];
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="url"></param>
    /// <returns></returns>
    public bool NeedsRequestBeMapped(string urlKey)
    {
      if (Uri.IsWellFormedUriString(urlKey, UriKind.Absolute))
      {
        // Example: Key="http://www.buglist.io/test/boom/ignaz.html"
        if (this.cache.ContainsKey(urlKey))
        {
          return true;
        }

        // http://www.buglist.io/ and HSTS enabled
        Uri tmpUri = new Uri(urlKey);
        string tmpRequestUrl = string.Format("{0}://{1}/", tmpUri.Scheme, tmpUri.Host);

        if (this.cache.ContainsKey(urlKey))
        {
          return true;
        }
      }

      return false;
    }

    #endregion


    #region PRIVATE

    private CacheSslStrip()
    {
    }

    #endregion


  }
}
