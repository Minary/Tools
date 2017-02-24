namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.Text.RegularExpressions;


  public partial class InjectCode
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

      if (HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords == null)
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

      foreach (DataTypes.InjectCodeConfigRecord tmpRecord in HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords)
      {
        string hostSearchPattern = "^" + Regex.Escape(tmpRecord.Host) + "$";
        string pathSearchPattern = "^" + Regex.Escape(tmpRecord.Path) + "$";

        if (Regex.Match(host, hostSearchPattern, RegexOptions.IgnoreCase).Success &&
            Regex.Match(path, pathSearchPattern, RegexOptions.IgnoreCase).Success)
        {
          this.pluginProperties.PluginHost.LoggingInst.LogMessage("InjectCode", ProxyProtocol.Undefined, Loglevel.Debug, "InjectCode.OnPostClientHeadersRequest(): Requesting \"{0}{1}\" -> \"{2}\"", host, path, tmpRecord.InjectionCodeFile);
          instruction.Instruction = Instruction.SendBackLocalFile;
          instruction.InstructionParameters.Data = tmpRecord.InjectionCodeFile;
          break;
        }
      }

      return instruction;
    }
  }
}
