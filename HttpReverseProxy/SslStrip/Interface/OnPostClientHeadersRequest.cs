namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxy.Plugin.SslStrip.Cache;
  using HttpReverseProxy.Plugin.SslStrip.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;

  public partial class SslStrip
  {

    /// <summary>
    /// 1. If requested host was not declared in configuration just forward peer system response to lClient (Config.SslStrippingConfigByHost)
    /// 2. If requested Url was detected to be redirected replace scheme, host and randomFileName by the redirection location
    /// 3. If requested host was flaged to use HTTPS because of HSTS, replace the http:// scheme by https
    /// </summary>
    public PluginInstruction OnPostClientHeadersRequest(RequestObj requestObj)
    {
      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      string requestedUrl = string.Format("{0}://{1}{2}", requestObj.ClientRequestObj.Scheme, requestObj.ClientRequestObj.Host, requestObj.ClientRequestObj.RequestLine.Path);

      // 1. If requested Url was HTML SSL stripped
      //    -> replace "http" by "https"
      if (CacheSslStrip.Instance.NeedsRequestBeMapped(requestedUrl))
      {
        HostRecord tmpHost = CacheSslStrip.Instance.GetElement(requestObj.ClientRequestObj.GetRequestedUrl());
        requestObj.ClientRequestObj.Scheme = tmpHost.Scheme;
        requestObj.ClientRequestObj.Host = tmpHost.Host;
        requestObj.ClientRequestObj.RequestLine.Path = tmpHost.Path;
        Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Info, "SslStrip.OnPostClientHeadersRequest(): SslStripped from {0} {1} to {2}://{3}{4}", requestObj.ClientRequestObj.RequestLine.MethodString, requestedUrl, tmpHost.Scheme, tmpHost.Host, tmpHost.Path);
      }

      // 2. If requested Url was detected to be redirected
      //    ->  replace "scheme://host/randomFileName" by the redirection location
      if (CacheRedirect.Instance.NeedsRequestBeMapped(requestedUrl))
      {
        HostRecord tmpHost = CacheRedirect.Instance.GetElement(requestObj.ClientRequestObj.GetRequestedUrl());
        requestObj.ClientRequestObj.Scheme = tmpHost.Scheme;
        requestObj.ClientRequestObj.Host = tmpHost.Host;
        requestObj.ClientRequestObj.RequestLine.Path = tmpHost.Path;
        Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Info, "SslStrip.OnPostClientHeadersRequest(): HTTP redirect(301/302) from {0} {1} to {2}://{3}{4}", requestObj.ClientRequestObj.RequestLine.MethodString, requestedUrl, tmpHost.Scheme, tmpHost.Host, tmpHost.Path);
      }

      // 3. If requested host was flaged to use HTTPS because of HSTS
      //    -> replace scheme "http://" by "https://"
      if (CacheHsts.Instance.GetElement(requestObj.ClientRequestObj.Host) != null)
      {
        Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Info, "SslStrip.OnPostClientHeadersRequest(): HSTS header set for \"{0}\"", requestObj.ClientRequestObj.Host);
        requestObj.ClientRequestObj.Scheme = "https";
      }

      return instruction;
    }
  }
}
