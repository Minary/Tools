namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;

  public partial class SslStrip
  {

    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <returns></returns>
    public PluginInstruction OnPostServerHeadersResponse(RequestObj requestObj)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      PluginInstruction ipPluginInstruction = this.ProcessServerResponseHeaders(requestObj);

      return ipPluginInstruction;
    }

    #endregion


    #region PRIVATE

    /// <summary>
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    public PluginInstruction ProcessServerResponseHeaders(RequestObj requestObj)
    {
      RedirectType redirType;
      PluginInstruction pluginInstruction = new PluginInstruction();

      // Handle HSTS header
      this.ProcessHstsHeader(requestObj);

      // Determine redirection mode
      redirType = this.DetermineRedirectType(requestObj);

      // The HTTP lClient request triggers a regular HTML data response.
      // 1. Transfer the peer system response (Server response string, headers, data)
      //
      //  -> DONT DO ANYTHING
      if (redirType == RedirectType.Http2http2XX)
      {
        // Set PluginInstruction values
        pluginInstruction.Instruction = Instruction.DoNothing;

        Logging.Instance.LogMessage(
                                    requestObj.Id,
                                    ProxyProtocol.Undefined,
                                    Loglevel.DEBUG,
                                    "SslStrip.ProcessServerResponseHeaders(): TYPE Http2http2XX, {0} \"{1}\" -> \"-\", host:{2}, MimeType:{3}",
                                    requestObj.ServerResponseObj.ContentTypeEncoding.ContentType,
                                    requestObj.ClientRequestObj.GetRequestedUrl(),
                                    requestObj.ClientRequestObj.Host,
                                    requestObj.ServerResponseObj.ContentTypeEncoding.ContentType);



      // The HTTP client request triggers a request to a HTTP Url
      // 1. Transfer the peer system response (Server response string, headers, data)
      //
      // -> DONT DO ANYTHING
      }
      else if (redirType == RedirectType.Http2Http3XX)
      {
        // Set PluginInstruction values
        pluginInstruction.Instruction = Instruction.DoNothing;

        Logging.Instance.LogMessage(
                                    requestObj.Id,
                                    ProxyProtocol.Undefined,
                                     Loglevel.DEBUG,
                                    "SslStrip.ProcessServerResponseHeaders(): TYPE Http2Http3XX \"{0}\" -> \"{1}\"",
                                    requestObj.ClientRequestObj.GetRequestedUrl(),
                                    requestObj.ServerResponseObj.ResponseHeaders["location"]);



      // SslStrip : The HTTP client request triggers a request to a HTTPS Url
      // 1. Cache the HTTP/HTTPS mapping
      // 2. Replace the "https" scheme in the redirect location by "http"
      // 3. Transfer the peer system response (Server response string, headers, data)
      }
      else if (redirType == RedirectType.Http2Https3XXDifferentUrl)
      {
        this.ProcessHeadersDifferentRedirectLocation(requestObj);

        // Set PluginInstruction values
        pluginInstruction.Instruction = Instruction.DoNothing;

        //// Http2Https3XXSameUrl         -> Remember redirect, strip SSL, request new Url    SSLCacheAndRedirectClient2RedirectLocation()

        Logging.Instance.LogMessage(
                                    requestObj.Id,
                                    ProxyProtocol.Undefined,
                                    Loglevel.DEBUG,
                                    "SslStrip.ProcessServerResponseHeaders(): TYPE Http2Https3XXDifferentUrl \"{0}\" -> \"{1}\"",
                                    requestObj.ClientRequestObj.GetRequestedUrl(),
                                    requestObj.ServerResponseObj.ResponseHeaders["location"]);



      // 1. Resend the same request again to the same Url but with "https" scheme instead of "http"
      // 2. Transfer the peer system response (Server response string, headers, data)
      }
      else if (redirType == RedirectType.Http2Https3XXSameUrl)
      {
       this.ProcessHeadersSameRedirectLocation(requestObj);

        // Set PluginInstruction values
        pluginInstruction.Instruction = Instruction.ReloadUrlWithHttps;

        Logging.Instance.LogMessage(
                                    requestObj.Id,
                                    ProxyProtocol.Undefined,
                                    Loglevel.DEBUG,
                                    "SslStrip.ProcessServerResponseHeaders(): TYPE Http2Https3XXSameUrl \"{0}\" -> \"{1}\" OldScheme:{2}",
                                    requestObj.ClientRequestObj.GetRequestedUrl(),
                                    requestObj.ServerResponseObj.ResponseHeaders["location"],
                                    requestObj.ClientRequestObj.Scheme);


      // This should never happen!!
      // No clue what to do at this point!
      }
      else
      {
        // Set PluginInstruction values
        pluginInstruction.Instruction = Instruction.DoNothing;

        Logging.Instance.LogMessage(
                                    requestObj.Id,
                                    ProxyProtocol.Undefined,
                                    Loglevel.DEBUG,
                                    "SslStrip.DoClientRequestProcessing(): TYPE definition error for Url \"{0}\" ",
                                    requestObj.ClientRequestObj.GetRequestedUrl());
      }

      return pluginInstruction;
    }

    #endregion

  }
}
