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
    public PluginInstruction OnPostServerHeadersResponse(RequestObj requestObj)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      // Remove Strict Transport Security (HSTS) header
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("strict-transport-security"))
        {
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.DEBUG, "Weaken.OnPostServerHeadersResponse(): Remove \"strict -transport-security: ...\"");
          requestObj.ServerResponseObj.ResponseHeaders.Remove("strict-transport-security");
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.INFO, "Weaken.WeakenClientRequestHeaders(EXCEPTION:Hsts): {0}", ex.Message);
      }

      // Remove "Set-Cookie ... secure"
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Set-Cookie") &&
            Regex.Match(requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].ToString(), @";\s+secure", RegexOptions.IgnoreCase).Success)
        {
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.INFO, "Weaken.OnPostServerHeadersResponse(): Remove \"secure\" cookie attribute.");

          string newCookieHeader = Regex.Replace(requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].ToString(), @";\s+secure", string.Empty, RegexOptions.IgnoreCase | RegexOptions.Multiline);
          requestObj.ServerResponseObj.ResponseHeaders.Remove("Set-Cookie");
          requestObj.ServerResponseObj.ResponseHeaders.Add("Set-Cookie", newCookieHeader);
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.INFO, @"Weaken.WeakenClientRequestHeaders(EXCEPTION:SetCookie secure): {0}", ex.Message);
      }

      // Remove "Set-Cookie ... HttpOnly"
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Set-Cookie") &&
            Regex.Match(requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].ToString(), @";\s+httponly", RegexOptions.IgnoreCase).Success)
        {
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.DEBUG, "Weaken.OnPostServerHeadersResponse(): Remove \"HttpOnly\" cookie attribute.");

          string newCookieHeader = Regex.Replace(requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].ToString(), @";\s+httponly", string.Empty, RegexOptions.IgnoreCase | RegexOptions.Multiline);
          requestObj.ServerResponseObj.ResponseHeaders.Remove("Set-Cookie");
          requestObj.ServerResponseObj.ResponseHeaders.Add("Set-Cookie", newCookieHeader);
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.INFO, @"Weaken.WeakenClientRequestHeaders(EXCEPTION:SetCookie HttpOnly): {0}", ex.Message);
      }

      return instruction;
    }
  }
}