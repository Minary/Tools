namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxy.Plugin.SslStrip.Cache;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System;
  using System.Collections.Concurrent;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;
  using SslStripConfig = HttpReverseProxy.Plugin.SslStrip.Config;


  public partial class SslStrip : IPlugin
  {

    #region MEMBERS

    private CacheHsts cacheHsts;
    private CacheRedirect cacheRedirect;
    private CacheSslStrip cacheSslStrip;
    private PluginProperties pluginProperties;
    private string sslStrippedData;
    private Dictionary<string, bool> sslStrippedHosts = new Dictionary<string, bool>();
    private Dictionary<string, string> sslStrippedUrls = new Dictionary<string, string>();
    private Config pluginConfig = new Config();
    private string configurationFileFullPath;

    #endregion


    #region PROPERTIES

    public string SslStrippedData { get { return this.sslStrippedData; } set { } }

    public Dictionary<string, bool> SslStrippedHosts { get { return this.sslStrippedHosts; } set { } }

    public Dictionary<string, string> SslStrippedUrls { get { return this.sslStrippedUrls; } set { } }

    public Config PluginConfig { get { return this.pluginConfig; } set { } }

    #endregion


    #region PUBLIC

    public SslStrip()
    {
      this.sslStrippedData = string.Empty;
      this.sslStrippedHosts = new Dictionary<string, bool>();
      this.sslStrippedUrls = new Dictionary<string, string>();

      this.cacheHsts = new CacheHsts();
      this.cacheRedirect = new CacheRedirect();

      this.pluginProperties = new PluginProperties()
      {
        Name = SslStripConfig.PluginName,
        Priority = SslStripConfig.PluginPriority,
        Version = SslStripConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", SslStripConfig.PluginName),
        IsActive = true,
        SupportedProtocols = ProxyProtocol.Http | ProxyProtocol.Https
      };
    }


    public void ProcessHstsHeader(RequestObj requestObj)
    {
      foreach (string tmpKey in requestObj.ServerResponseObj.ResponseHeaders.Keys)
      {
        if (tmpKey.ToLower() != "strict-transport-security")
        {
          continue;
        }

        if (this.cacheHsts.HstsCache.ContainsKey(requestObj.ClientRequestObj.GetRequestedUrl()))
        {
          continue;
        }

        try
        {
          this.cacheHsts.AddElement(requestObj.ClientRequestObj.GetRequestedUrl());
        }
        catch
        {
        }

        break;
      }
    }



    /// <summary>
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    /// <returns></returns>
    public RedirectType DetermineRedirectType(RequestObj requestObj)
    {
      string redirectHeader = string.Empty;
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Location"))
        {
          redirectHeader = requestObj.ServerResponseObj.ResponseHeaders["Location"][0];
        }
        else
        {
          redirectHeader = string.Empty;
        }
      }
      catch (Exception)
      {
      }

      bool hasRedirectHeader = string.IsNullOrEmpty(redirectHeader) ? false : true;
      Uri tmpUri = null;

      try
      {
        tmpUri = hasRedirectHeader ? new Uri(redirectHeader) : null;
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "SslStrip.DetermineRedirectType(EXCEPTION): Parsing the requested URI \"{0}\" causes the following exception: {1}\nStacktrace: {2}", redirectHeader, ex.Message, ex.StackTrace);
        return RedirectType.Error;
      }

      string requestScheme = "http";
      string requestUrl = string.Format("{0}{1}", requestObj.ClientRequestObj.Host, requestObj.ClientRequestObj.RequestLine.Path);
      string redirectUrl = hasRedirectHeader ? (string.Format("{0}{1}", tmpUri.Host, tmpUri.PathAndQuery)) : string.Empty;
      string redirectScheme = hasRedirectHeader ? tmpUri.Scheme.ToLower() : string.Empty;

      Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "SslStrip.DetermineRedirectType(): {0}://{1} -> Redirected:{2} to {3}://{4}", requestScheme, requestUrl, hasRedirectHeader, redirectScheme, redirectUrl);

      if (requestScheme == "http" && hasRedirectHeader == false)
      {
        return RedirectType.Http2http2XX;
      }
      else if (requestScheme == "http" && hasRedirectHeader == true && redirectScheme == "http")
      {
        return RedirectType.Http2Http3XX;
      }
      else if (requestScheme == "http" && hasRedirectHeader == true && redirectScheme == "https" && requestUrl != redirectUrl)
      {
        return RedirectType.Http2Https3XXDifferentUrl;
      }
      else if (requestScheme == "http" && hasRedirectHeader == true && redirectScheme == "https" && requestUrl == redirectUrl)
      {
        return RedirectType.Http2Https3XXSameUrl;
      }
      else
      {
        return RedirectType.Error;
      }
    }

    #endregion


    #region PRIVATE

    /// <summary>
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    private void ProcessHeadersSameRedirectLocation(RequestObj requestObj)
    {
      // Cache HTTP2HTTPS redirect Location
      string redirectLocationHttps = requestObj.ServerResponseObj.ResponseHeaders["Location"][0];
      string requestedLocation = requestObj.ClientRequestObj.GetRequestedUrl();

      try
      {
        this.cacheRedirect.AddElement(requestObj.Id, requestedLocation, redirectLocationHttps);
      }
      catch
      {
      }

      // Change scheme from http to https
      requestObj.ProxyProtocol = ProxyProtocol.Https;

      Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "SslStrip.ProcessHeadersSameRedirectLocation(): Redirecting from {0} to {1}", requestedLocation, redirectLocationHttps);

      //string refreshHeader = string.Format("{0}; Url={1}", 1, requestObj.ClientRequestObj.GetRequestedUrl());
      //if (requestObj.ServerResponseMetaDataObj.ResponseHeaders.ContainsKey("Refresh"))
      //  requestObj.ServerResponseMetaDataObj.ResponseHeaders.Remove("Refresh");

      //requestObj.ServerResponseMetaDataObj.ResponseHeaders.Add("Refresh", refreshHeader);
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    private void ProcessHeadersDifferentRedirectLocation(RequestObj requestObj)
    {
      // 1. Determine and cache HTTP2HTTPS redirect Location
      string redirectLocationHttps = requestObj.ServerResponseObj.ResponseHeaders["Location"][0];
      ////      string redirectLocationHttp = requestObj.ServerWebResponse.GetResponseHeader("Location");
      string redirectLocationHttp = requestObj.ServerResponseObj.ResponseHeaders["Location"][0];
      string requestedLocation = requestObj.ClientRequestObj.GetRequestedUrl();

      Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "SslStrip.ProcessHeadersDifferentRedirectLocation(): TYPE Http2Https3XXSameUrl {0} -> {1}", requestedLocation, redirectLocationHttps);

      if (redirectLocationHttp.StartsWith("https:"))
      {
        redirectLocationHttp = Regex.Replace(redirectLocationHttp, "^https:", "http:");
      }

      try
      {
        this.cacheRedirect.AddElement(requestObj.Id, redirectLocationHttp, redirectLocationHttps);
      }
      catch
      {
      }

      // 2. Replace cRemoteSocket response "Location" header by SSLStripped version
      if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Location"))
      {
        requestObj.ServerResponseObj.ResponseHeaders.Remove("Location");
      }

      requestObj.ServerResponseObj.ResponseHeaders.Add("Location", new List<string>() { redirectLocationHttp });
    }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="inputData"></param>
    /// <param name="tagList"></param>
    /// <returns></returns>
    private string ReplaceRelevantTags(RequestObj requestObj, string inputData, ConcurrentDictionary<string, string> tagList)
    {
      if (inputData == null)
      {
        throw new Exception("Input data is invalid");
      }

      if (tagList == null)
      {
        throw new Exception("Tag cache is invalid");
      }

      foreach (string tmpKey in tagList.Keys)
      {
        if (Regex.Match(inputData, tmpKey).Success)
        {
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "SslStrip.ReplaceRelevantTags(): Match found:     |{0}|{1}|", tmpKey, tagList[tmpKey]);
        }
        else
        {
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "SslStrip.ReplaceRelevantTags(): No match found:  |{0}|{1}|", tmpKey, tagList[tmpKey]);
        }

        inputData = Regex.Replace(inputData, Regex.Escape(tmpKey), tagList[tmpKey], RegexOptions.Singleline | RegexOptions.Multiline | RegexOptions.IgnoreCase);
      }

      return inputData;
    }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="inputData"></param>
    /// <param name="theTagStripRegex"></param>
    /// <param name="foundHttpsTags"></param>
    /// <param name="cacheRecords"></param>
    private void LocateAllTags(string inputData, Regex theTagStripRegex, ConcurrentDictionary<string, string> foundHttpsTags, ConcurrentDictionary<string, string> cacheRecords)
    {
      if (inputData == null)
      {
        throw new Exception("Input data is invalid");
      }

      if (theTagStripRegex == null)
      {
        throw new Exception("Search regex catalog is invalid");
      }

      if (foundHttpsTags == null)
      {
        throw new Exception("Tag cache is invalid");
      }

      Match matches = theTagStripRegex.Match(inputData);

      while (matches.Success)
      {
        string matchedHost = matches.Groups[1].Value;
        string matchedPath = matches.Groups[2].Value;

        // Process tag and cache the http/https records
        string newTag = Regex.Replace(matches.Groups[0].Value, "https://", "http://");
        foundHttpsTags.TryAdd(matches.Groups[0].Value, newTag);

        // Keep a copy of both URLs in the cache
        cacheRecords.TryAdd(string.Format("{0}{1}", matchedHost.Replace("https://", "http://"), matchedPath), string.Format("{0}{1}", matchedHost, matchedPath));

        // Find next match
        matches = matches.NextMatch();
      }
    }

    #endregion


    #region INTERFACE IMPLEMENTATION: Properties    

    public PluginProperties Config { get { return this.pluginProperties; } set { this.pluginProperties = value; } }

    #endregion


    #region INTERFACE IMPLEMENTATION: IComparable

    public int CompareTo(IPlugin other)
    {
      if (other == null)
      {
        return 1;
      }

      if (this.Config.Priority > other.Config.Priority)
      {
        return 1;
      }
      else if (this.Config.Priority < other.Config.Priority)
      {
        return -1;
      }
      else
      {
        return 0;
      }
    }

    #endregion

  }
}
