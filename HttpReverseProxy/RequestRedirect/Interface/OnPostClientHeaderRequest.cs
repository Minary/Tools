namespace HttpReverseProxy.Plugin.RequestRedirect
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;


  public partial class RequestRedirect
  {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <returns></returns>
    public PluginInstruction OnPostClientHeadersRequest(RequestObj requestObj)
    {
      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (HttpReverseProxy.Plugin.RequestRedirect.Config.RequestRedirectRecords == null)
      {
        return instruction;
      }

      if (requestObj.ClientRequestObj.ClientRequestHeaders == null || 
          requestObj.ClientRequestObj.ClientRequestHeaders.Count <= 0)
      {
        return instruction;
      }

      if (!requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Host"))
      {
        return instruction;
      }

      string host = requestObj.ClientRequestObj.ClientRequestHeaders["Host"][0].ToLower();
      string path = requestObj.ClientRequestObj.RequestLine.Path;

      foreach (DataTypes.RequestRedirectConfigRecord tmpRecord in HttpReverseProxy.Plugin.RequestRedirect.Config.RequestRedirectRecords)
      {
        if (tmpRecord.HostnameRegex.Match(host).Success &&
            tmpRecord.PathRegex.Match(path).Success)
        {
          instruction.Instruction = Instruction.RedirectToNewUrl;
          instruction.InstructionParameters.Data = tmpRecord.ReplacementResource;
          instruction.InstructionParameters.Status = tmpRecord.RedirectType;
          instruction.InstructionParameters.StatusDescription = tmpRecord.RedirectDescription;
          break;
        }
      }

      return instruction;
    }
  }
}

