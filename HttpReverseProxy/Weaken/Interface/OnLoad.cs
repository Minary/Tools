namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib.DataTypes.Interface;


  public partial class Weaken
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public void OnLoad(IPluginHost pluginHost)
    {
      // Set plugin properties
      this.pluginProperties.PluginHost = pluginHost;

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
