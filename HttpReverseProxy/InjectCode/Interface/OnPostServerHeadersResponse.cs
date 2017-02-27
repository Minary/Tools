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
    /// <param name="requestObj"></param>
    /// <returns></returns>
    public PluginInstruction OnPostServerHeadersResponse(RequestObj requestObj)
    {
      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      // Return if the plugin does not contain at least one injectcode records.
      if (HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords == null ||
          HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords.Count <= 0)
      {
        return instruction;
      }

      // Return if the client did not send the Host HTTP header.
      if (requestObj.ClientRequestObj.ClientRequestHeaders == null ||
          requestObj.ClientRequestObj.ClientRequestHeaders.Count <= 0)
      {
        return instruction;
      }

      if (!requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Host"))
      {
        return instruction;
      }

      // Return if the server response does not have the type "text/html"
      if (!requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Content-Type") ||
          requestObj.ServerResponseObj.ResponseHeaders["Content-Type"].ToString().ToLower() == "text/html")
      {
        return instruction;
      }

      if (HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords.ContainsKey(requestObj.ClientRequestObj.Host))
      {
        var configRecord = HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords[requestObj.ClientRequestObj.Host];
        string pathPattern = HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords[requestObj.ClientRequestObj.Host].Path;

        if (Regex.Match(requestObj.ClientRequestObj.RequestLine.Path, pathPattern, RegexOptions.IgnoreCase).Success)
        {
          this.pluginProperties.PluginHost.LoggingInst.LogMessage("InjectCode", ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnPostServerHeadersResponse(): Requesting \"{0}{1}\". Injection -> \"{2}\"", configRecord.Host, configRecord.Path, System.IO.Path.GetFileName(configRecord.InjectionCodeFile));
          instruction.Instruction = Instruction.InjectLocalFileIntoStream;
          instruction.InstructionParameters.DataDict.Add("file", configRecord.InjectionCodeFile);
          instruction.InstructionParameters.DataDict.Add("data", System.IO.File.ReadAllText(configRecord.InjectionCodeFile));
          instruction.InstructionParameters.DataDict.Add("tag", configRecord.Tag);
          instruction.InstructionParameters.DataDict.Add("tagRegex", string.Format(@"(<\s*{0}[^>]*>)", configRecord.Tag));
          instruction.InstructionParameters.DataDict.Add("position", configRecord.Position.ToLower().Trim());
        }
      }

      return instruction;
    }
  }
}
