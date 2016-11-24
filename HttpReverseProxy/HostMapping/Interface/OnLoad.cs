namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.Interface;
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
      // Set plugin properties
      this.pluginProperties = new PluginProperties()
      {
        Name = HostMappingConfig.PluginName,
        Priority = HostMappingConfig.PluginPriority,
        Version = HostMappingConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", HostMappingConfig.PluginName),
        PluginHost = pluginHost,
        IsActive = true,
      };

      // Parse configuration file
      this.configurationFileFullPath = Path.Combine(this.pluginProperties.PluginDirectory, HostMappingConfig.ConfigFileName);
      if (string.IsNullOrEmpty(this.configurationFileFullPath))
      {
        return;
      }

      try
      {
        this.pluginConfig.ParseConfigurationFile(this.configurationFileFullPath);
      }
      catch (System.IO.FileNotFoundException)
      {
        string tmpConfigFile = Path.GetFileName(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("HostMapping", Logging.Level.INFO, "HostMapping.OnLoad(): Config file \"...{0}\" does not exist", tmpConfigFile);
      }
      catch (Exception ex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("HostMapping", Logging.Level.INFO, "HostMapping.OnLoad(EXCEPTION): {0}", ex.Message);
      }

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}