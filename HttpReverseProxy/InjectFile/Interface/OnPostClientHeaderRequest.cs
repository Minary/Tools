namespace HttpReverseProxy.Plugin.InjectFile
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.Text.RegularExpressions;


  public partial class InjectFile
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

      if (HttpReverseProxy.Plugin.InjectFile.Config.InjectFileRecords == null)
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

      foreach (DataTypes.InjectFileConfigRecord tmpRecord in HttpReverseProxy.Plugin.InjectFile.Config.InjectFileRecords)
      {
        string hostSearchPattern = "^" + Regex.Escape(tmpRecord.Host) + "$";
        string pathSearchPattern = "^" + Regex.Escape(tmpRecord.Path) + "$";

        if (Regex.Match(host, hostSearchPattern, RegexOptions.IgnoreCase).Success &&
            Regex.Match(path, pathSearchPattern, RegexOptions.IgnoreCase).Success)
        {
          this.pluginProperties.PluginHost.LoggingInst.LogMessage("InjectFile", ProxyProtocol.Undefined, Loglevel.Debug, "InjectFile.OnPostClientHeadersRequest(): Requesting \"{0}{1}\" -> \"{2}\"", host, path, tmpRecord.ReplacementResource);
          instruction.Instruction = Instruction.SendBackLocalFile;
          instruction.InstructionParameters.Data = tmpRecord.ReplacementResource;
          break;
        }
      }

      return instruction;
    }
  }
}
