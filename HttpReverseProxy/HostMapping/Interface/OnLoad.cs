namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System;
  using System.IO;
  using HostMappingConfig = HttpReverseProxy.Plugin.HostMapping.Config;


  public partial class HostMapping
  {

    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public void OnLoad(IPluginHost pluginHost)
    {
      this.pluginProperties.PluginHost = pluginHost;

      // Parse configuration file
      this.configurationFileFullPath = Path.Combine(this.pluginProperties.PluginDirectory, HostMappingConfig.ConfigFileName);
      if (string.IsNullOrEmpty(this.configurationFileFullPath))
      {
        return;
      }

      try
      {
        this.pluginConfig.ParseConfigurationFile(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("HostMapping", ProxyProtocol.Undefined, Loglevel.Info, "HostMapping.OnLoad(): Loaded {0} configuration record(s)", HostMappingConfig.Mappings?.Count ?? 0);
      }
      catch (System.IO.FileNotFoundException)
      {
        string tmpConfigFile = Path.GetFileName(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("HostMapping", ProxyProtocol.Undefined, Loglevel.Info, "HostMapping.OnLoad(): Config file \"...{0}\" does not exist", tmpConfigFile);
      }
      catch (Exception ex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("HostMapping", ProxyProtocol.Undefined, Loglevel.Info, "HostMapping.OnLoad(EXCEPTION): {0}", ex.Message);
      }

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}