namespace HttpReverseProxy.Plugin.SslStrip.Cache
{
  using HttpReverseProxy.Plugin.SslStrip.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.Collections.Generic;
  using System.Text.RegularExpressions;


  public class CacheRedirect
  {

    #region PROPERTIES

    public Dictionary<string, HostRecord> RedirectCache { get; set; } = new Dictionary<string, HostRecord>();

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

      Logging.Instance.LogMessage(id, ProxyProtocol.Undefined, Loglevel.Debug, "CacheRedirect.Cache.AddElement(): {0} => {1}", keyLocation, valueLocation);
      HostRecord tmpHost = new HostRecord("GET", ProxyProtocol.Https, tmpUriValue.Host, tmpUriValue.PathAndQuery);
      this.RedirectCache.Add(keyLocation, tmpHost);
    }

    /// <summary>
    ///
    /// </summary>
    public void EnumerateCache()
    {
      foreach (var tmpKey in this.RedirectCache.Keys)
      {
        Logging.Instance.LogMessage("SslStrip.CacheRedirect", ProxyProtocol.Undefined, Loglevel.Debug, "SslStrip.CacheRedirect.EnumerateCache(): Key:{0} Value:{1}, Counter:{2}", tmpKey, this.RedirectCache[tmpKey].Url, RedirectCache[tmpKey].Counter);
      }
    }


    /// <summary>
    ///
    /// </summary>
    public void ResetCache()
    {
      if (this.RedirectCache != null)
      {
        this.RedirectCache.Clear();
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

      if (this.RedirectCache.ContainsKey(urlKey))
      {
        return this.RedirectCache.Remove(urlKey);
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

      if (!this.RedirectCache.ContainsKey(urlKey))
      {
        return null;
      }

      return this.RedirectCache[urlKey];
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
        if (this.RedirectCache.ContainsKey(urlKey))
        {
          return true;
        }

        // http://www.buglist.io/ and HSTS enabled
        var tmpUri = new Uri(urlKey);
        var tmpRequestUrl = $"{tmpUri.Scheme}://{tmpUri.Host}/";
        if (this.RedirectCache.ContainsKey(urlKey))
        {
          return true;
        }
      }

      return false;
    }

    #endregion
    
  }
}
