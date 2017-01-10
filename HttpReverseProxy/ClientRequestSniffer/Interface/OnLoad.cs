namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib.Interface;


  public partial class ClientRequestSniffer
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public void OnLoad(IPluginHost pluginHost)
    {
      this.pluginProperties.PluginHost = pluginHost;

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
