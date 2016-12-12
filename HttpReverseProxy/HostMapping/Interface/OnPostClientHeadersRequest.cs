namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.Exceptions;

  public partial class HostMapping
  {

    public PluginInstruction OnPostClientHeadersRequest(RequestObj requestObj)
    {
      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (!string.IsNullOrEmpty(requestObj.ClientRequestObj.Host) &&
          Plugin.HostMapping.Config.Mappings != null && 
          Plugin.HostMapping.Config.Mappings.Count > 0 &&
          Plugin.HostMapping.Config.Mappings.ContainsKey(requestObj.ClientRequestObj.Host))
      {
        if (requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Host"))
        {
          requestObj.ClientRequestObj.ClientRequestHeaders.Remove("Host");
          requestObj.ClientRequestObj.ClientRequestHeaders.Add("Host", Plugin.HostMapping.Config.Mappings[requestObj.ClientRequestObj.Host].Item2);

          requestObj.ClientRequestObj.Scheme = Plugin.HostMapping.Config.Mappings[requestObj.ClientRequestObj.Host].Item1;
          requestObj.ClientRequestObj.Host = Plugin.HostMapping.Config.Mappings[requestObj.ClientRequestObj.Host].Item2;
        }
      }

      return instruction;
    }
  }
}
