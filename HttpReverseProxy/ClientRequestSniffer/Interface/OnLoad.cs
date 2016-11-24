namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib.Interface;
  using System.IO;
  using ClientSnifferConfig = HttpReverseProxy.Plugin.ClientRequestSniffer.Config;


  public partial class ClientRequestSniffer
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public void OnLoad(IPluginHost pluginHost)
    {
      // Set plugin properties
      this.pluginProperties = new PluginProperties()
      {
        Name = ClientSnifferConfig.PluginName,
        Priority = ClientSnifferConfig.PluginPriority,
        Version = ClientSnifferConfig.PluginVersion,
        PluginDirectory = Directory.GetCurrentDirectory(),
        PluginHost = pluginHost,
        IsActive = true,
      };

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
