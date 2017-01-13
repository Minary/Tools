namespace HttpReverseProxy.Plugin.Inject
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.Exceptions;
  using System.Text.RegularExpressions;


  public partial class Inject
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

      if (HttpReverseProxy.Plugin.Inject.Config.InjectRecords == null)
      {
        return instruction;
      }

      if (requestObj.ClientRequestObj.ClientRequestHeaders == null || requestObj.ClientRequestObj.ClientRequestHeaders.Count <= 0)
      {
        return instruction;
      }

      if (!requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Host"))
      {
        return instruction;
      }

      string host = requestObj.ClientRequestObj.ClientRequestHeaders["Host"][0];
      string path = requestObj.ClientRequestObj.RequestLine.Path;

      foreach (DataTypes.InjectConfigRecord tmpRecord in HttpReverseProxy.Plugin.Inject.Config.InjectRecords)
      {
        string hostSearchPattern = "^" + Regex.Escape(tmpRecord.Host) + "$";
        string pathSearchPattern = "^" + Regex.Escape(tmpRecord.Path) + "$";

        if (Regex.Match(host, hostSearchPattern, RegexOptions.IgnoreCase).Success &&
            Regex.Match(path, pathSearchPattern, RegexOptions.IgnoreCase).Success)
        {
          if (tmpRecord.Type == DataTypes.InjectType.File)
          {
            instruction.Instruction = Instruction.SendBackLocalFile;
            instruction.InstructionParameters.Data = tmpRecord.ReplacementResource;
            break;
          }
          else if (tmpRecord.Type == DataTypes.InjectType.URL)
          {
            instruction.Instruction = Instruction.RedirectToNewUrl;
            instruction.InstructionParameters.Data = tmpRecord.ReplacementResource;
            break;
          }
          else
          {
            continue;
          }
        }
      }

      return instruction;
    }
  }
}
