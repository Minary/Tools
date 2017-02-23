namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
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

      if (string.IsNullOrEmpty(requestObj.ClientRequestObj.Host))
      {
        return instruction;
      }

      string hostName = requestObj.ClientRequestObj.Host.ToLower();
      if (Plugin.HostMapping.Config.Mappings != null &&
          Plugin.HostMapping.Config.Mappings.Count > 0 &&
          Plugin.HostMapping.Config.Mappings.ContainsKey(hostName))
      {
        if (requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Host"))
        {
          this.pluginProperties.PluginHost.LoggingInst.LogMessage(
                                                                  "HostMapping",
                                                                  ProxyProtocol.Undefined,
                                                                  Loglevel.Debug,
                                                                  "HostMapping.OnPostClientHeadersRequest(): Replacing host \"{0}\" by \"{1}\"",
                                                                  requestObj.ClientRequestObj.ClientRequestHeaders["Host"][0].ToString(),
                                                                  Plugin.HostMapping.Config.Mappings[hostName].Item2);
          requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Clear();
          requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Add(Plugin.HostMapping.Config.Mappings[hostName].Item2);

          requestObj.ClientRequestObj.Scheme = Plugin.HostMapping.Config.Mappings[hostName].Item1;
          requestObj.ClientRequestObj.Host = Plugin.HostMapping.Config.Mappings[hostName].Item2;
        }
      }

      return instruction;
    }
  }
}
