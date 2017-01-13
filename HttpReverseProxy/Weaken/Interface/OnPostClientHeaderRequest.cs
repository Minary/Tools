namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System;
  using System.Text.RegularExpressions;

  public partial class Weaken
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public PluginInstruction OnPostClientHeadersRequest(RequestObj requestObj)
    {
      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (requestObj.ClientRequestObj.ClientRequestHeaders == null || requestObj.ClientRequestObj.ClientRequestHeaders.Count <= 0)
      {
        return instruction;
      }

      // 1. Replace Connection: keep-alive by Connection: close
      // Todo: Not sure if this Connection:close is a good idea
      //try
      //{
      //  if (requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Connection") &&
      //      requestObj.ClientRequestObj.ClientRequestHeaders["Connection"].ToString() == "keep-alive")
      //  {
      //    Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "Weaken.OnPostClientHeaderRequest(): Replace  \"Connection: keep-alive\" by \"Connection: close\"");
      //    requestObj.ClientRequestObj.ClientRequestHeaders.Remove("Connection");
      //    requestObj.ClientRequestObj.ClientRequestHeaders.Add("Connection", "close");
      //  }
      //}
      //catch (Exception ex)
      //{
      //  Logging.Instance.LogMessage(requestObj.Id, Logging.Level.ERROR, @"Weaken.OnPostClientHeaderRequest(EXCEPTION): {0}", ex.Message);
      //}

      // Accept-Encoding: gzip, deflate
      // 2. Remove Accept-Encoding header entirely
      try
      {
        if (requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Accept-Encoding") &&
            Regex.Match(requestObj.ClientRequestObj.ClientRequestHeaders["Accept-Encoding"][0], @"(gzip|deflate|compress)", RegexOptions.IgnoreCase).Success)
        {
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.DEBUG, "Weaken.OnPostClientHeaderRequest(): Remove  \"Accept -Encoding: gzip|deflate|compress\"");
          requestObj.ClientRequestObj.ClientRequestHeaders.Remove("Accept-Encoding");
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.ERROR, @"SslStrip.WeakenClientRequestHeaders(EXCEPTION): {0}", ex.Message);
      }

      // Upgrade: TLS/1.0
      // Connection: Upgrade
      // 3. Remove Upgrade:TLS headers
      try
      {
        if (requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Upgrade") &&
            Regex.Match(requestObj.ClientRequestObj.ClientRequestHeaders["Upgrade"][0], "^TLS.*", RegexOptions.IgnoreCase).Success)
        {
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.DEBUG, "Weaken.OnPostClientHeaderRequest(): Remove  \"Upgrade: TLS.*\"");
          requestObj.ClientRequestObj.ClientRequestHeaders.Remove("Upgrade");
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.ERROR, @"SslStrip.WeakenClientRequestHeaders(EXCEPTION): {0}", ex.Message);
      }

      return instruction;
    }
  }
}
