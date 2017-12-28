namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System;
  using System.Collections.Generic;
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
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "Weaken.OnPostServerHeadersResponse(): Remove \"strict -transport-security: ...\"");
          requestObj.ServerResponseObj.ResponseHeaders.Remove("strict-transport-security");
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, "Weaken.WeakenClientRequestHeaders(EXCEPTION:Hsts): {0}", ex.Message);
      }


      // Remove X-Frame-Options (obsolete, actually)
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("X-Frame-Options"))
        {
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "Weaken.OnPostServerHeadersResponse(): Remove \" X-Frame-Options: ...\"");
          requestObj.ServerResponseObj.ResponseHeaders.Remove("X-Frame-Options");
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, "Weaken.WeakenClientRequestHeaders(EXCEPTION:Hsts): {0}", ex.Message);
      }


      // Remove Content - Security - Policy
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Content-Security-Policy"))
        {
          Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "Weaken.OnPostServerHeadersResponse(): Remove \" Content-Security-Policy: ...\"");
          requestObj.ServerResponseObj.ResponseHeaders.Remove("Content-Security-Policy");
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, "Weaken.WeakenClientRequestHeaders(EXCEPTION:Hsts): {0}", ex.Message);
      }


      
      // Remove "Set-Cookie ... secure"
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Set-Cookie"))
        {
          List<string> newServerHeaders = new List<string>();
          bool listValuesChanged = false;

          foreach (string tmpValue in requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"])
          {
            if (Regex.Match(tmpValue, @";\s+secure", RegexOptions.IgnoreCase).Success)
            {
              Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, "Weaken.OnPostServerHeadersResponse(): Remove \"secure\" cookie attribute.");
              string newCookieHeader = Regex.Replace(tmpValue, @";\s+secure", string.Empty, RegexOptions.IgnoreCase | RegexOptions.Multiline);

              newServerHeaders.Add(newCookieHeader);
              listValuesChanged = true;
            }
            else
            {
              newServerHeaders.Add(tmpValue);
            }
          }

          if (listValuesChanged == true)
          {
            requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].Clear();
            requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].AddRange(newServerHeaders);
          }
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, @"Weaken.WeakenClientRequestHeaders(EXCEPTION:SetCookie secure): {0}", ex.Message);
      }

      // Remove "Set-Cookie ... HttpOnly"
      try
      {
        if (requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Set-Cookie"))
        {
          List<string> newServerHeaders = new List<string>();
          bool listValuesChanged = false;

          foreach (string tmpValue in requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"])
          {
            if (Regex.Match(tmpValue, @";\s+httponly", RegexOptions.IgnoreCase).Success)
            {
              Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "Weaken.OnPostServerHeadersResponse(): Remove \"HttpOnly\" cookie attribute.");
              string newCookieHeader = Regex.Replace(tmpValue, @";\s+httponly", string.Empty, RegexOptions.IgnoreCase | RegexOptions.Multiline);

              newServerHeaders.Add(newCookieHeader);
              listValuesChanged = true;
            }
            else
            {
              newServerHeaders.Add(tmpValue);
            }
          }

          if (listValuesChanged == true)
          {
            requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].Clear();
            requestObj.ServerResponseObj.ResponseHeaders["Set-Cookie"].AddRange(newServerHeaders);
          }
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, @"Weaken.WeakenClientRequestHeaders(EXCEPTION:SetCookie HttpOnly): {0}", ex.Message);
      }

      return instruction;
    }
  }
}