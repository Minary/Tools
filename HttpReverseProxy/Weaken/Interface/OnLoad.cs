namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib.Interface;
  using System.IO;
  using WeakenConfig = HttpReverseProxy.Plugin.Weaken.Config;

  public partial class Weaken
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
        Name = WeakenConfig.PluginName,
        Priority = WeakenConfig.PluginPriority,
        Version = WeakenConfig.PluginVersion,
        PluginDirectory = Directory.GetCurrentDirectory(),
        PluginHost = pluginHost,
        IsActive = true,
      };

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
